//! Synchronous polling watch APIs.
//!
//! This first Rust SDK watcher is intentionally small and read-backed. It
//! reuses [`Tn::read`](crate::Tn::read), remembers how many entries it has
//! already yielded, and returns newly visible entries on each [`Watch::poll`]
//! call.
//!
//! It is not a true file-tail implementation: it does not subscribe to
//! filesystem notifications, keep a background task alive, or stream partial log
//! writes. That tradeoff keeps the default crate free of async runtime
//! requirements while the public SDK shape is still settling. Future
//! `notify`/async implementations can build behind feature flags without
//! changing this v0 polling contract.
//!
//! ```no_run
//! use std::time::Duration;
//! use tn_proto::{PollingWatchOptions, Result, Tn, WatchOptions, WatchStart};
//!
//! # fn main() -> Result<()> {
//! let tn = Tn::init("tn.yaml")?;
//! let mut watch = tn.polling_watch(PollingWatchOptions {
//!     start: WatchStart::Latest,
//!     event_type_prefix: Some("order.".to_string()),
//!     poll_interval: Duration::from_millis(250),
//!     ..WatchOptions::default()
//! })?;
//!
//! for entry in watch.wait_for_entries(Duration::from_secs(5))? {
//!     println!("{entry:?}");
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};
#[cfg(feature = "watch")]
use std::{
    fs::OpenOptions,
    path::PathBuf,
    sync::mpsc::{self, Receiver, RecvTimeoutError},
};

use crate::entry::Entry;
use crate::tn::{ReadOptions, Tn};
use crate::Result;
#[cfg(feature = "watch")]
use notify::{RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher};

/// Backwards-compatible alias for the SDK's v0 polling watcher.
///
/// New code may prefer this name when it is useful to distinguish the
/// read-backed watcher from future native file notification watchers.
pub type PollingWatch<'a> = Watch<'a>;

/// Backwards-compatible alias for [`WatchOptions`].
pub type PollingWatchOptions = WatchOptions;

/// Options for [`Tn::native_watch`](crate::Tn::native_watch).
///
/// Native watching is available behind the `watch` feature. It subscribes to
/// filesystem notifications for the active log file and uses the existing
/// polling watcher to decrypt and filter entries after a change arrives.
#[cfg(feature = "watch")]
#[derive(Debug, Clone)]
pub struct NativeWatchOptions {
    /// Options used by the underlying polling/read-backed watcher.
    pub polling: PollingWatchOptions,
}

#[cfg(feature = "watch")]
impl Default for NativeWatchOptions {
    fn default() -> Self {
        Self {
            polling: PollingWatchOptions::default(),
        }
    }
}

/// Where a watcher should start reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchStart {
    /// Start at the beginning of the current read view.
    Beginning,
    /// Start after the entries visible when the watcher is created.
    Latest,
}

/// Options for [`Tn::watch`](crate::Tn::watch).
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Initial cursor position.
    pub start: WatchStart,
    /// Options forwarded to [`Tn::read`](crate::Tn::read) on each poll.
    pub read: ReadOptions,
    /// Sleep duration used by [`Watch::sleep_then_poll`].
    pub poll_interval: Duration,
    /// Optional exact event type to yield.
    ///
    /// If `event_type_prefix` is also set, yielded entries must satisfy both
    /// filters.
    pub event_type: Option<String>,
    /// Optional event type prefix to yield.
    ///
    /// If `event_type` is also set, yielded entries must satisfy both filters.
    pub event_type_prefix: Option<String>,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            start: WatchStart::Latest,
            read: ReadOptions::default(),
            poll_interval: Duration::from_millis(300),
            event_type: None,
            event_type_prefix: None,
        }
    }
}

/// Synchronous polling watcher over a [`Tn`] handle.
///
/// Create one with [`Tn::watch`](crate::Tn::watch), then call [`Watch::poll`]
/// when your application is ready to drain newly visible entries. Use
/// [`Watch::wait_for_entries`] when you want a bounded blocking wait.
///
/// The watcher tracks progress by entry count in the current
/// [`Tn::read`](crate::Tn::read) view. If that view shrinks, the cursor resets
/// and the next poll starts from the beginning of the visible read view.
pub struct Watch<'a> {
    tn: &'a Tn,
    options: WatchOptions,
    cursor: usize,
}

impl<'a> Watch<'a> {
    pub(crate) fn new(tn: &'a Tn, options: WatchOptions) -> Result<Self> {
        let cursor = match options.start {
            WatchStart::Beginning => 0,
            WatchStart::Latest => tn.read(options.read)?.len(),
        };
        Ok(Self {
            tn,
            options,
            cursor,
        })
    }

    /// Return entries that became visible since the previous poll.
    ///
    /// This calls [`Tn::read`](crate::Tn::read) every time. For high-throughput
    /// log tailing, prefer a future file-backed watcher once one exists.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if reading or decrypting the underlying log
    /// fails.
    pub fn poll(&mut self) -> Result<Vec<Entry>> {
        let entries = self.tn.read(self.options.read)?;
        if self.cursor > entries.len() {
            self.cursor = 0;
        }
        let out = entries[self.cursor..]
            .iter()
            .filter(|entry| self.accepts(entry))
            .cloned()
            .collect();
        self.cursor = entries.len();
        Ok(out)
    }

    /// Sleep for `poll_interval`, then call [`Watch::poll`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if reading or decrypting the underlying log
    /// fails after the sleep completes.
    pub fn sleep_then_poll(&mut self) -> Result<Vec<Entry>> {
        std::thread::sleep(self.options.poll_interval);
        self.poll()
    }

    /// Poll until at least one entry is visible or `timeout` elapses.
    ///
    /// This method never spawns a background thread. It checks once
    /// immediately, then sleeps in `poll_interval` increments until entries
    /// arrive or the timeout expires. A zero timeout behaves like
    /// [`Watch::poll`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if reading or decrypting the underlying log
    /// fails.
    pub fn wait_for_entries(&mut self, timeout: Duration) -> Result<Vec<Entry>> {
        let first = self.poll()?;
        if !first.is_empty() || timeout.is_zero() {
            return Ok(first);
        }

        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Ok(Vec::new());
            }
            let remaining = timeout.saturating_sub(elapsed);
            std::thread::sleep(self.options.poll_interval.min(remaining));
            let entries = self.poll()?;
            if !entries.is_empty() {
                return Ok(entries);
            }
        }
    }

    /// Return the current number of entries already consumed by this watcher.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Convert this watcher into a finite iterator.
    ///
    /// The iterator yields entries one at a time until no new entries arrive
    /// for `idle_timeout`, then ends. Each item is a [`Result`] so read errors
    /// can surface through ordinary iterator adapters such as `collect`.
    pub fn into_iter_until_idle(self, idle_timeout: Duration) -> WatchIter<'a> {
        WatchIter {
            watch: self,
            idle_timeout,
            buffer: VecDeque::new(),
            done: false,
        }
    }

    fn accepts(&self, entry: &Entry) -> bool {
        let event_type = entry.event_type();
        if let Some(expected) = &self.options.event_type {
            if event_type != Some(expected.as_str()) {
                return false;
            }
        }
        if let Some(prefix) = &self.options.event_type_prefix {
            if !event_type.is_some_and(|value| value.starts_with(prefix)) {
                return false;
            }
        }
        true
    }
}

/// Finite iterator returned by [`Watch::into_iter_until_idle`].
///
/// It drains entries from the underlying watcher and stops after the watcher is
/// idle for the configured timeout.
pub struct WatchIter<'a> {
    watch: Watch<'a>,
    idle_timeout: Duration,
    buffer: VecDeque<Entry>,
    done: bool,
}

impl Iterator for WatchIter<'_> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if let Some(entry) = self.buffer.pop_front() {
            return Some(Ok(entry));
        }

        match self.watch.wait_for_entries(self.idle_timeout) {
            Ok(entries) if entries.is_empty() => {
                self.done = true;
                None
            }
            Ok(entries) => {
                self.buffer = entries.into();
                self.buffer.pop_front().map(Ok)
            }
            Err(err) => {
                self.done = true;
                Some(Err(err))
            }
        }
    }
}

/// Feature-gated synchronous native file notification watcher.
///
/// `NativeWatch` uses the `notify` crate to wake when the active log file
/// changes, then delegates decryption, verification flags, and event filtering
/// to the same read-backed logic used by [`PollingWatch`]. This keeps native
/// watch behavior aligned with the rest of the SDK while avoiding a required
/// async runtime.
#[cfg(feature = "watch")]
pub struct NativeWatch<'a> {
    polling: PollingWatch<'a>,
    events: Receiver<notify::Result<notify::Event>>,
    _watcher: RecommendedWatcher,
    log_path: PathBuf,
}

#[cfg(feature = "watch")]
impl<'a> NativeWatch<'a> {
    pub(crate) fn new(tn: &'a Tn, options: NativeWatchOptions) -> Result<Self> {
        let polling = Watch::new(tn, options.polling)?;
        let log_path = tn.log_path().to_path_buf();
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        let (tx, events) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |event| {
            let _ = tx.send(event);
        })?;
        watcher.watch(&log_path, RecursiveMode::NonRecursive)?;

        Ok(Self {
            polling,
            events,
            _watcher: watcher,
            log_path,
        })
    }

    /// Return entries that became visible since the previous poll.
    ///
    /// This method does not wait for a filesystem event; it is useful when the
    /// caller already woke for another reason and wants to drain the current
    /// read view.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if reading or decrypting the underlying log
    /// fails.
    pub fn poll(&mut self) -> Result<Vec<Entry>> {
        self.polling.poll()
    }

    /// Wait for native file events until entries arrive or `timeout` elapses.
    ///
    /// The method checks once immediately, then blocks on the native watcher.
    /// When a file event arrives it drains newly visible entries through
    /// [`NativeWatch::poll`]. A zero timeout behaves like [`NativeWatch::poll`].
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the native watcher reports an error or
    /// when reading/decrypting the underlying log fails.
    pub fn wait_for_entries(&mut self, timeout: Duration) -> Result<Vec<Entry>> {
        let first = self.poll()?;
        if !first.is_empty() || timeout.is_zero() {
            return Ok(first);
        }

        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Ok(Vec::new());
            }

            match self.events.recv_timeout(timeout.saturating_sub(elapsed)) {
                Ok(Ok(_event)) => {
                    let entries = self.poll()?;
                    if !entries.is_empty() {
                        return Ok(entries);
                    }
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(RecvTimeoutError::Timeout) => return Ok(Vec::new()),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(crate::Error::InvalidArgument(format!(
                        "native watcher disconnected for {}",
                        self.log_path.display()
                    )));
                }
            }
        }
    }

    /// Return the current number of entries already consumed by this watcher.
    pub fn cursor(&self) -> usize {
        self.polling.cursor()
    }
}
