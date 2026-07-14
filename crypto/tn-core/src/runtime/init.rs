//! Lifecycle: open or create a ceremony and tear it down.
//!
//! Holds the [`Runtime`] load path ([`Runtime::init`] /
//! [`Runtime::init_with_storage`] / [`Runtime::init_with_options`] /
//! [`Runtime::ephemeral`]), the process-wide log-level controls
//! ([`Runtime::set_level`] and friends), the cheap accessors
//! ([`Runtime::did`] / [`Runtime::log_path`] / [`Runtime::group_names`]),
//! and the explicit [`Runtime::close`] flush. The disk-side helpers these
//! call (session rotation, chain seeding, cipher construction) live in the
//! `log_rotation` and `cipher_build` submodules.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::chain::ChainState;
use crate::log_file::LogFileWriter;
use crate::signing::DeviceKey;
use crate::{Error, Result};

use super::cipher_build::{build_group_states, write_fresh_btn_ceremony, FreshBtnCeremonyOptions};
use super::log_rotation::{
    build_pel_writer, path_with_backup_suffix, read_rotation_config, rotate_log_on_session_start,
    rotation_first_time_this_process, scan_for_ceremony_init, seed_chain_from_log,
    seed_chain_from_template,
};
use super::util::{current_timestamp, is_absolute_xplat_path, resolve};
use super::{level_value, log_level, Runtime, RuntimeInitOptions, LOG_LEVEL_THRESHOLD};

impl Runtime {
    /// Set the process-wide log-level threshold. Verbs at a lower level
    /// short-circuit before any work happens. Mirrors Python
    /// `tn.set_level()` and TS `TNClient.setLevel()`. (AVL J3.2.)
    ///
    /// Accepts the four standard names ("debug" / "info" / "warning" /
    /// "error") case-insensitively, plus "warn" as an alias for warning,
    /// and the empty string ("always emit").
    ///
    /// The severity-less [`Runtime::log`] always emits regardless of the
    /// threshold — it's an explicit "this is a fact" primitive.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`](crate::Error::InvalidConfig) when `level`
    /// is not one of the recognized names.
    pub fn set_level(level: &str) -> Result<()> {
        let normalized = level.to_lowercase();
        let v = match normalized.as_str() {
            "" => -1,
            "debug" => log_level::DEBUG,
            "info" => log_level::INFO,
            "warning" | "warn" => log_level::WARNING,
            "error" => log_level::ERROR,
            other => {
                return Err(Error::InvalidConfig(format!(
                    "set_level: unknown level {other:?}; expected debug/info/warning/error"
                )));
            }
        };
        LOG_LEVEL_THRESHOLD.store(v, Ordering::Relaxed);
        Ok(())
    }

    /// Set the threshold from a numeric value (10/20/30/40 etc.). Lets
    /// callers plug in custom severities without round-tripping through
    /// the string map.
    pub fn set_level_value(level: i32) {
        LOG_LEVEL_THRESHOLD.store(level, Ordering::Relaxed);
    }

    /// Return the active threshold as a level name when it matches one
    /// of the standard four; otherwise return its numeric stringified
    /// value.
    pub fn get_level() -> String {
        match LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) {
            log_level::DEBUG => "debug".to_string(),
            log_level::INFO => "info".to_string(),
            log_level::WARNING => "warning".to_string(),
            log_level::ERROR => "error".to_string(),
            other => other.to_string(),
        }
    }

    /// True iff `level` would currently emit. Use as a guard for
    /// expensive log-arg construction (mirrors stdlib
    /// `logging.Logger.isEnabledFor`).
    pub fn is_enabled_for(level: &str) -> bool {
        level_value(level) >= LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed)
    }

    /// Load the ceremony at `yaml_path` and return a ready-to-use
    /// `Runtime`. This is the front door — it backs `tn.init()` /
    /// `tn init`.
    ///
    /// Reads the ceremony yaml (resolving any `extends:` chain), loads
    /// the device key + master index key from the keystore, builds a
    /// cipher for every declared group, seeds the per-event_type hash
    /// chain from the existing log, and opens the append-only writer.
    ///
    /// Side effects on a successful load:
    /// - **Session rotation.** On the first `init` for a given log path
    ///   in this process, an existing non-empty log is rolled to
    ///   `<name>.1` (older backups shift forward) so the new session
    ///   writes a fresh file. Opt out with yaml
    ///   `handlers[*].rotate_on_init: false`. Re-`init` in the same
    ///   process appends instead of rotating.
    /// - **Ceremony attestation.** A *fresh* ceremony (no prior
    ///   `tn.ceremony.init` anywhere in the log) writes one as its first
    ///   attested event. A `tn.agents.policy_published` event is written
    ///   when the loaded `agents.md` policy hash differs from the last
    ///   published one.
    /// - **Stdout handler.** A JSON-line stdout handler is attached
    ///   unless `TN_NO_STDOUT=1` or the yaml `handlers:` list omits a
    ///   `stdout` entry.
    ///
    /// Native filesystem-backed factory: delegates to
    /// [`Runtime::init_with_storage`] with an `FsStorage`. Use that
    /// method directly when you need an injected storage backend (wasm,
    /// tests, in-memory sandboxes).
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::Error::Io) if the yaml, device seed, or
    /// `index_master.key` can't be read.
    /// [`Error::InvalidConfig`](crate::Error::InvalidConfig) on malformed
    /// yaml, a keystore DID that disagrees with `device.device_identity`,
    /// a wrong-length master key, or a group that can't be built (e.g. a
    /// btn group with neither state nor kit on disk). [`Error::Yaml`](crate::Error::Yaml)
    /// on a yaml parse failure. [`Error::NotImplemented`](crate::Error::NotImplemented)
    /// for a JWE group (those run through the Python runtime in this
    /// plan). The ceremony-init / policy-published attestations are
    /// best-effort and never fail the load.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tn_core::Runtime;
    /// use std::path::Path;
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::init(Path::new("tn.yaml"))?;
    /// println!("loaded ceremony for {}", rt.did());
    /// # Ok(())
    /// # }
    /// ```
    pub fn init(yaml_path: &Path) -> Result<Self> {
        crate::perf::init_from_env();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
        Self::init_with_storage(yaml_path, storage)
    }

    /// Load a ceremony with a caller-supplied [`Storage`] backend.
    ///
    /// Thin wrapper over [`Runtime::init_with_options`] using
    /// `RuntimeInitOptions::default()`. See that method for the full
    /// docstring; [`Runtime::init`] is the everyday native entry point.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::init_with_options`].
    ///
    /// [`Storage`]: crate::storage::Storage
    pub fn init_with_storage(
        yaml_path: &Path,
        storage: Arc<dyn crate::storage::Storage>,
    ) -> Result<Self> {
        Self::init_with_options(yaml_path, storage, RuntimeInitOptions::default())
    }

    /// Load a ceremony with a caller-supplied [`Storage`] backend and
    /// extra options.
    ///
    /// The storage handle is stored on the returned `Runtime` so
    /// subsequent emit / read / admin calls route file I/O through
    /// the same backend. Today only the load-bearing reads inside
    /// `init` consult the storage; the rest of `Runtime` is being
    /// migrated to route through it too. See the `storage` field
    /// comment for the migration status.
    ///
    /// `yaml_path` is read via `storage.read_bytes`; on wasm with a
    /// `JsStorageAdapter` that means the JS callback is invoked.
    ///
    /// `opts` lets the caller suppress side-effects that are
    /// inappropriate when the SDK has already initialized the
    /// ceremony out-of-band — see [`RuntimeInitOptions`].
    ///
    /// This is the shared body behind [`Runtime::init`] and
    /// [`Runtime::init_with_storage`]; see [`Runtime::init`] for the
    /// session-rotation and attestation side effects.
    ///
    /// # Errors
    ///
    /// Same set as [`Runtime::init`]: [`Error::Io`](crate::Error::Io) /
    /// [`Error::InvalidConfig`](crate::Error::InvalidConfig) /
    /// [`Error::Yaml`](crate::Error::Yaml) /
    /// [`Error::NotImplemented`](crate::Error::NotImplemented) from
    /// reading the yaml + keystore and building each group's cipher.
    ///
    /// [`Storage`]: crate::storage::Storage
    // Holds the ceremony-mint vs ceremony-load invariant in one place:
    // the chain seed, fresh-detection scan, and post-construction
    // attestations stay inline so the "what state must be coherent before
    // we hand back a Runtime" check is reviewable as a unit. Per-group
    // cipher construction and the PEL writer build are factored into
    // `build_group_states` / `build_pel_writer`; the body is still long
    // enough to warrant the line-count allow.
    #[allow(clippy::too_many_lines)]
    pub fn init_with_options(
        yaml_path: &Path,
        storage: Arc<dyn crate::storage::Storage>,
        opts: RuntimeInitOptions,
    ) -> Result<Self> {
        // Call site 1: yaml read. Routes through Storage so a wasm
        // `JsStorageAdapter` can satisfy the request from its JS-side
        // callback rather than `std::fs::read_to_string`.
        let yaml_bytes = storage.read_bytes(yaml_path).map_err(Error::Io)?;
        let yaml_str = std::str::from_utf8(&yaml_bytes)
            .map_err(|e| Error::InvalidConfig(format!("yaml is not valid UTF-8: {e}")))?;
        let expanded = crate::config::substitute_env_vars(yaml_str, yaml_path)?;
        // Resolve `extends:` chain through the same Storage backend so
        // stream yamls written by `createFreshCeremony` (which carry
        // `extends: ../default/tn.yaml`) load correctly under wasm too.
        // Matches Python `_resolve_extends` semantics.
        let cfg = crate::config::parse_with_extends(&expanded, yaml_path, storage.as_ref())?;
        let yaml_dir = yaml_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        let keystore = resolve(&yaml_dir, Path::new(&cfg.keystore.path));

        // Call site 2: device-key load (32-byte seed at <keystore>/local.private).
        let seed_path = keystore.join(crate::identity::DEVICE_SEED_FILENAME);
        let seed_bytes = storage.read_bytes(&seed_path).map_err(Error::Io)?;
        let device = DeviceKey::from_private_bytes(&seed_bytes)?;
        if device.did() != cfg.device.device_identity {
            return Err(Error::InvalidConfig(format!(
                "keystore DID {} does not match yaml device.device_identity {}",
                device.did(),
                cfg.device.device_identity
            )));
        }

        // Call site 3: master index key (32 raw bytes at <keystore>/index_master.key).
        // Filename matches Python tn/config.py.
        let master_path = keystore.join("index_master.key");
        let master_index_key: [u8; 32] = storage
            .read_bytes(&master_path)
            .map_err(Error::Io)?
            .try_into()
            .map_err(|_| Error::InvalidConfig("index_master.key must be 32 bytes".into()))?;

        // Call site 4 (inside the loop): per-group cipher construction
        // reads `<group>.btn.state` / `<group>.btn.mykit` through storage.
        let (groups, btn_admin, btn_mykit) =
            build_group_states(&cfg, &master_index_key, &keystore, &storage, &device)?;

        // Honor `logs.path` from the yaml. Relative paths resolve against
        // the yaml directory; absolute paths are used as-is. Default is
        // `./.tn/logs/tn.ndjson` relative to yaml dir (set by config's serde
        // default if the yaml doesn't mention `logs:`).
        let configured = Path::new(&cfg.logs.path);
        let log_path = if is_absolute_xplat_path(configured) {
            configured.to_path_buf()
        } else {
            yaml_dir.join(configured)
        };

        // Session-start rotation: when the existing log has content
        // from a prior PROCESS, roll it to `<name>.1` (shifting any
        // older `.1`..`.N` backups forward up to `backup_count`) so
        // the new session writes into a fresh file. Matches stdlib
        // `logging` mental model and the Python `FileRotatingHandler`
        // / TS `NodeRuntime` behavior.
        //
        // Process-scoped guard: the rotation must only happen ONCE per
        // process per log path. A common test/dev pattern is:
        //
        //     tn.init(yaml)         # first init: rotate (new session)
        //     tn.info(...)
        //     tn.flush_and_close()
        //     tn.init(yaml)         # re-init in SAME process: append, do not rotate
        //     tn.read()             # must see what we just wrote
        //
        // Without the guard, every Runtime::init in the same process
        // would rotate the log and the chain would break. We track which
        // log paths we've already rotated in this process via a global
        // set, populated lazily on first rotation per path.
        // Honors yaml `handlers[*].rotate_on_init: false` to opt out.
        let (rotate_on_init, backup_count) = read_rotation_config(&cfg.handlers);
        if rotate_on_init && rotation_first_time_this_process(&log_path) {
            rotate_log_on_session_start(&log_path, backup_count, &storage);
        }

        // Parse the main-log template once. The parsed template is
        // reused both for the chain seed (literal vs templated) and
        // for the `LogWriters` construction below.
        let log_path_template = crate::path_template::PathTemplate::parse(
            &cfg.logs.path,
            &yaml_dir,
            &cfg.ceremony.id,
            device.did(),
        )?;

        let chain = ChainState::new();

        // Seed chain state from the main log and check for a prior
        // ceremony.init. Templated `logs.path` walks every rendered
        // `.ndjson` under the template's parent directory; literal
        // paths just walk the one file. Wiring the templated seed
        // closes a silent regression introduced when templated paths
        // moved off the Python emit path — without it, chained
        // templated ceremonies reset every event_type's
        // (sequence, prev_hash) to (1, ZERO) on each restart.
        let mut saw_ceremony_init = if log_path_template.is_templated() {
            seed_chain_from_template(&log_path_template, &chain, &storage)?
        } else {
            seed_chain_from_log(&log_path, &chain, &storage)?
        };

        // Admin events have their own per-event-type chains even when they
        // are routed away from the main log. Seed those tips before opening
        // the writer pool so the first admin emit after a restart continues
        // the existing chain instead of resetting to sequence 1.
        if cfg.ceremony.protocol_events_location != "main_log" {
            let pel_template = crate::path_template::PathTemplate::parse(
                &cfg.ceremony.protocol_events_location,
                &yaml_dir,
                &cfg.ceremony.id,
                device.did(),
            )?;
            let saw_admin_init = if pel_template.is_templated() {
                seed_chain_from_template(&pel_template, &chain, &storage)?
            } else {
                seed_chain_from_log(&pel_template.render("", ""), &chain, &storage)?
            };
            saw_ceremony_init |= saw_admin_init;
        }

        // Session rotation makes the current main log empty; a prior
        // `tn.ceremony.init` may live on a rotation backup. Scan the
        // shifted `<log>.1`..`.N` files so we don't re-emit
        // `tn.ceremony.init` on every session start (which would
        // pollute the admin log with one Frank-own event per session
        // and break cross-publisher reads of admin snapshots).
        if !saw_ceremony_init {
            for n in 1..=backup_count.max(1) {
                let backup = path_with_backup_suffix(&log_path, n);
                if storage.exists(&backup) && scan_for_ceremony_init(&backup, &storage)? {
                    saw_ceremony_init = true;
                    break;
                }
            }
        }

        // A ceremony is fresh iff no prior tn.ceremony.init exists in the log(s).
        // Checking main-log existence would miss the case where
        // protocol_events_location routes tn.* events to a separate file.
        let is_fresh = !saw_ceremony_init;

        // Construct the writer pool from the template hoisted above.
        // Init-time tokens (`{yaml_dir}`, `{ceremony_id}`, `{did}`)
        // were substituted at parse time. The dispatcher routes
        // per-emit to a literal writer (one shared `LogFileWriter`)
        // OR a lazy pool keyed by rendered path.
        let log_writer = if log_path_template.is_templated() {
            crate::log_file::LogWriters::Templated {
                template: log_path_template,
                storage: Arc::clone(&storage),
                writers: Mutex::new(std::collections::HashMap::new()),
            }
        } else {
            // Literal path — render once (returns the path with
            // any relative root resolved against yaml_dir) and
            // open the single writer.
            let path = log_path_template.render("", "");
            let writer = LogFileWriter::open(&path, Arc::clone(&storage))?;
            crate::log_file::LogWriters::Literal {
                path,
                writer: Arc::new(Mutex::new(writer)),
            }
        };

        // PEL writer mirrors the main log writer for `tn.*` admin
        // events when `protocol_events_location != "main_log"`. The
        // pre-0.4.2a8 emit path opened a fresh file handle per admin
        // emit via `storage.append_bytes`, paying ~150 us of Windows
        // syscall floor (CreateFileW + WriteFile + CloseHandle).
        // Routing PEL emits through a `LogWriters` pool reuses the
        // pinned-handle, lock-cache, and offset-skip machinery and
        // closes that asymmetry with the main path.
        //
        // PEL=="main_log" shadow: emit-time `pel_routed` is always
        // false in that mode, so this field is never read. We still
        // build a placeholder that mirrors the main log so
        // `flush_all` at shutdown is symmetric and the struct field
        // always holds a valid `LogWriters`.
        let pel_writer = build_pel_writer(
            &log_writer,
            &cfg.ceremony.protocol_events_location,
            &yaml_dir,
            &cfg.ceremony.id,
            device.did(),
            &storage,
        )?;

        // Call site 5: agents.md policy load routes through storage so
        // a wasm consumer's JS adapter can supply the file (or report
        // it absent).
        let agent_policies =
            match crate::agents_policy::load_policy_file_with_storage(&yaml_dir, &storage) {
                Ok(opt) => opt,
                Err(Error::Io(_)) => None,
                Err(e) => return Err(e),
            };

        // 0.4.2a7: pre-compute the field-routing table, public
        // membership set, and the set of groups whose policy is
        // public so emit_inner doesn't rebuild them per call. All
        // three are pure functions of the loaded `Config` —
        // invalidate only by re-init (which builds a fresh Runtime
        // anyway).
        let field_to_groups = cfg.field_to_groups()?;
        let public_set: std::collections::HashSet<String> =
            cfg.public_fields.iter().cloned().collect();
        let public_groups: std::collections::HashSet<String> = cfg
            .groups
            .iter()
            .filter(|(_, gspec)| gspec.policy == "public")
            .map(|(gname, _)| gname.clone())
            .collect();

        let rt = Self {
            yaml_path: yaml_path.to_path_buf(),
            cfg,
            device,
            chain,
            groups,
            log_writer,
            pel_writer,
            log_path,
            master_index_key,
            btn_admin,
            btn_mykit,
            keystore,
            owned_tempdir: None,
            agent_policies,
            handlers: Mutex::new(Vec::new()),
            storage,
            // Honor $TN_RUN_ID if the host (e.g. the Python wrapper) has
            // already minted one for this process. Otherwise mint a fresh
            // UUID. Either way every emit stamps the same `run_id` so
            // `Runtime::read` can default-filter to "this run only".
            run_id: std::env::var("TN_RUN_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| Uuid::new_v4().simple().to_string()),
            field_to_groups,
            public_set,
            public_groups,
        };

        // Post-construction side effects: attach the default stdout
        // handler, honor a yaml-baked log level, and write the
        // fresh-ceremony attestations. All best-effort — see the helper.
        rt.apply_post_init_effects(is_fresh, &opts);

        Ok(rt)
    }

    /// Reload this runtime from its current `tn.yaml`, preserving ownership
    /// metadata such as the tempdir created by [`Runtime::ephemeral`].
    ///
    /// This is useful after admin operations mutate `tn.yaml`: callers get a
    /// freshly parsed config and rebuilt group state without accidentally
    /// dropping the temporary ceremony directory for ephemeral runtimes.
    ///
    /// # Errors
    ///
    /// Same as [`Runtime::init_with_options`].
    pub fn reload_with_options(
        &mut self,
        storage: Arc<dyn crate::storage::Storage>,
        opts: RuntimeInitOptions,
    ) -> Result<()> {
        let yaml_path = self.yaml_path.clone();
        let owned_tempdir = self.owned_tempdir.take();
        let mut next = Self::init_with_options(&yaml_path, storage, opts)?;
        next.owned_tempdir = owned_tempdir;
        *self = next;
        Ok(())
    }

    /// Run the best-effort side effects after a `Runtime` is constructed in
    /// [`Runtime::init_with_options`]: attach the default stdout handler,
    /// honor a yaml-baked `ceremony.log_level`, and on a fresh ceremony
    /// write the `tn.ceremony.init` and `tn.agents.policy_published`
    /// attestations.
    ///
    /// Every step here is best-effort: a failed attestation or bad level
    /// name is logged and swallowed so a stale yaml field or a transient
    /// write error never fails the load. `opts` gates the two attestations
    /// for SDK wrappers that own those lifecycles out-of-band.
    fn apply_post_init_effects(&self, is_fresh: bool, opts: &RuntimeInitOptions) {
        // Default-on stdout handler: emit every envelope as a JSON line on
        // stdout in addition to the configured file/sink handlers. Mirrors
        // Python's `tn.init(stdout=True)` default and the TS SDK's
        // `TNClient` default. Opt-out via:
        //
        //   * ``TN_NO_STDOUT=1`` (env, all sinks)
        //   * yaml ``handlers: [...]`` declared with no ``kind: stdout``
        //     entry — yaml-as-contract per FINDINGS S0.4. The shipping
        //     ``create_fresh`` writes ``handlers: [file.rotating, stdout]``
        //     so the operator can edit/remove the entry to silence stdout
        //     for both admin and user emits without having to set the
        //     env var.
        let stdout_entry = self
            .cfg
            .handlers
            .iter()
            .find(|h| h.get("kind").and_then(|v| v.as_str()) == Some("stdout"));
        let yaml_silences_stdout = !self.cfg.handlers.is_empty() && stdout_entry.is_none();
        if std::env::var("TN_NO_STDOUT").as_deref() != Ok("1") && !yaml_silences_stdout {
            // Honour an explicit ``format:`` on the yaml stdout entry so a
            // yaml that asks for json gets json by default. The
            // ``TN_STDOUT_FORMAT`` env var still wins (resolved per-emit
            // inside the handler).
            let format = stdout_entry
                .and_then(|h| h.get("format"))
                .and_then(|v| v.as_str())
                .map(crate::handlers::StdoutFormat::parse)
                .unwrap_or_default();
            self.add_handler(Arc::new(
                crate::handlers::StdoutHandler::with_format_and_filter(
                    format,
                    crate::handlers::spec::FilterSpec::default(),
                ),
            ));
        }

        // Honor an optional yaml `ceremony.log_level` so operators can
        // bake the threshold into config (AVL J3.2). Programmatic
        // `Runtime::set_level` calls are sticky across re-inits in the
        // same process, so only apply the yaml value when the threshold
        // is still at the floor default (DEBUG).
        if !self.cfg.ceremony.log_level.is_empty()
            && LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) == log_level::DEBUG
        {
            // Best-effort: bad level names are logged + ignored so init
            // doesn't fail on a stale yaml field.
            if let Err(e) = Runtime::set_level(&self.cfg.ceremony.log_level) {
                log::warn!(
                    "ceremony.log_level={:?} ignored: {e}",
                    self.cfg.ceremony.log_level
                );
            }
        }

        // Fresh ceremony: emit tn.ceremony.init as the first attested event.
        // The reload path does not emit this (only fresh creation). See spec §2.1.
        //
        // `opts.skip_ceremony_init_emit` short-circuits the auto-emit even on a
        // fresh ceremony. SDK wrappers that bootstrap the ceremony from
        // another runtime (e.g. TS `NodeRuntime` lazily attaching a
        // `WasmRuntime` mid-process) set this to avoid double-attesting
        // the ceremony from two runtime instances.
        if is_fresh && !opts.skip_ceremony_init_emit {
            let now = current_timestamp();
            let mut init_fields = serde_json::Map::new();
            init_fields.insert(
                "ceremony_id".into(),
                serde_json::json!(self.cfg.ceremony.id),
            );
            init_fields.insert("cipher".into(), serde_json::json!(self.cfg.ceremony.cipher));
            // NOTE: do NOT add `device_identity` here. It is the mandatory
            // reserved envelope scalar (hashed first in the row_hash
            // preimage — docs/spec/row-hash.md) and `build_envelope`
            // always writes it at envelope root. On any ceremony whose
            // yaml lists `device_identity` under public_fields (every
            // Python/TS-written ceremony via DEFAULT_PUBLIC_FIELDS),
            // adding it here too routes it into the public field block so
            // the writer hashes it twice (scalar + public) while
            // spec-correct readers exclude the reserved scalar and hash it
            // once — the two disagree and `tn.ceremony.init` fails
            // row_hash verify cross-SDK. The admin catalog schema for
            // tn.ceremony.init was updated to match (no device_identity
            // field); the reducer reads it from the envelope scalar.
            init_fields.insert("created_at".into(), serde_json::json!(now));
            if let Err(e) = self.emit("info", "tn.ceremony.init", init_fields) {
                log::warn!(
                    "ceremony_init attestation failed: event_type=tn.ceremony.init error={e}"
                );
            }
        }

        // Emit tn.agents.policy_published when the loaded policy hash differs
        // from the most recent published one in the local logs (or no prior
        // event exists). Mirrors Python `_maybe_emit_policy_published`.
        // SDK wrappers (TS NodeRuntime) that own this lifecycle on their
        // side set `skip_policy_published_emit` to avoid the duplicate.
        if !opts.skip_policy_published_emit {
            if let Err(e) = self.maybe_emit_policy_published() {
                log::warn!("tn.agents.policy_published emit failed: {e}");
            }
        }
    }

    /// Build a runtime backed by a freshly-minted ceremony in a private
    /// tempdir. The tempdir is owned by the returned `Runtime` and is
    /// deleted when the runtime is dropped.
    ///
    /// Mirrors the ergonomics of Python's `tn.session()` / TS
    /// `TNClient.ephemeral()` for tests and one-shot scripts where the
    /// caller doesn't care about persisting the ceremony.
    ///
    /// Always uses `cipher: btn` because (a) it's hermetic — no JWE
    /// keypair wiring required — and (b) it's the cipher the cross-SDK
    /// test surface targets first.
    ///
    /// # Errors
    ///
    /// [`Error::Io`](crate::Error::Io) if the tempdir can't be created or
    /// the fresh ceremony can't be minted to disk, plus any error from
    /// the subsequent [`Runtime::init`] of the minted ceremony.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tn_core::Runtime;
    ///
    /// # fn main() -> tn_core::Result<()> {
    /// let rt = Runtime::ephemeral()?; // throwaway btn ceremony in a tempdir
    /// rt.info("smoke.test", serde_json::Map::new())?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn ephemeral() -> Result<Self> {
        let td = tempfile::Builder::new()
            .prefix("tn-ephemeral-")
            .tempdir()
            .map_err(Error::Io)?;
        let yaml_path = td.path().join("tn.yaml");
        write_fresh_btn_ceremony(td.path(), FreshBtnCeremonyOptions::ephemeral())
            .map_err(Error::Io)?;

        let mut rt = Self::init(&yaml_path)?;
        rt.owned_tempdir = Some(td);
        Ok(rt)
    }

    /// This runtime's `did:key:z…`.
    pub fn did(&self) -> &str {
        self.device.did()
    }

    /// Identifier stamped on events emitted by this runtime instance.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Path to the main ndjson log.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Names of groups declared in the active config.
    pub fn group_names(&self) -> Vec<String> {
        self.cfg.groups.keys().cloned().collect()
    }

    /// Current configured index/key epoch for one group.
    pub fn group_index_epoch(&self, group: &str) -> Result<u64> {
        self.cfg
            .groups
            .get(group)
            .map(|spec| spec.index_epoch)
            .ok_or_else(|| Error::InvalidConfig(format!("unknown group {group:?}")))
    }

    /// Borrow the `.tn/config/agents.md` policy document loaded at init.
    ///
    /// `None` when the ceremony has no policy file. This is the same
    /// document the emit-side splice and the `tn.agents.policy_published`
    /// lifecycle event read; language bindings surface it as their
    /// `agents.policy()` accessor.
    pub fn agent_policy_doc(&self) -> Option<&crate::agents_policy::PolicyDocument> {
        self.agent_policies.as_ref()
    }

    /// Explicit close: flush every open log writer and consume `self`.
    ///
    /// Dropping a `Runtime` without calling `close` is fine; `File`'s own
    /// Drop impl flushes OS buffers. Calling `close` gives you a
    /// `Result` you can surface if flushing errored.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())` — the underlying flush is
    /// best-effort. The `Result` is kept so a future fail-on-flush
    /// tightening is non-breaking.
    pub fn close(self) -> Result<()> {
        // Hand the LogWriters dispatchers off — for literal paths
        // this flushes the single writer; for templated pools it
        // walks every cached per-rendered-path writer. `pel_writer`
        // is a shadow of `log_writer` when PEL=="main_log"; its
        // separate `flush_all` is a no-op there (Arc clones, no
        // distinct writers), and a real flush when PEL is split.
        self.log_writer.flush_all();
        self.pel_writer.flush_all();
        Ok(())
    }

    /// Splice `tn.agents` policy fields into `fields` per spec §2.6.
    ///
    /// Looks up `event_type` in the cached policy doc; if a template
    /// exists, fills the six tn.agents fields via `setdefault` semantics
    /// (existing keys win). The yaml-declared `tn.agents` group routes
    /// those six field names automatically; this just populates them.
    pub(crate) fn splice_agent_policy(&self, event_type: &str, fields: &mut Map<String, Value>) {
        let Some(doc) = &self.agent_policies else {
            return;
        };
        let Some(t) = doc.templates.get(event_type) else {
            return;
        };
        fields
            .entry("instruction".to_string())
            .or_insert_with(|| Value::String(t.instruction.clone()));
        fields
            .entry("use_for".to_string())
            .or_insert_with(|| Value::String(t.use_for.clone()));
        fields
            .entry("do_not_use_for".to_string())
            .or_insert_with(|| Value::String(t.do_not_use_for.clone()));
        fields
            .entry("consequences".to_string())
            .or_insert_with(|| Value::String(t.consequences.clone()));
        fields
            .entry("on_violation_or_error".to_string())
            .or_insert_with(|| Value::String(t.on_violation_or_error.clone()));
        let policy_str = format!(
            "{}#{}@{}#{}",
            t.path, t.event_type, t.version, t.content_hash
        );
        fields
            .entry("policy".to_string())
            .or_insert_with(|| Value::String(policy_str));
    }

    /// Walk every log file (main + admin) and return the `content_hash`
    /// of the most recent `tn.agents.policy_published` event, or `None`.
    ///
    /// Decrypts each readable group's plaintext and merges into the
    /// envelope dict before lookup so it works whether the publisher
    /// listed the policy fields under `public_fields:` or routed them
    /// into the default group.
    fn last_policy_published_hash(&self) -> Option<String> {
        let mut paths: Vec<PathBuf> = Vec::new();
        if self.log_path.exists() {
            paths.push(self.log_path.clone());
        }
        let pel = &self.cfg.ceremony.protocol_events_location;
        if pel != "main_log" {
            let resolved = self.resolve_pel("tn.agents.policy_published");
            if resolved != self.log_path && resolved.exists() {
                paths.push(resolved);
            }
        }

        let mut last_ts = String::new();
        let mut last_hash: Option<String> = None;
        for path in &paths {
            let Ok(entries) = self.read_from(path) else {
                continue;
            };
            for entry in entries {
                if entry.envelope.get("event_type").and_then(Value::as_str)
                    != Some("tn.agents.policy_published")
                {
                    continue;
                }
                let ts = entry
                    .envelope
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                // Try envelope root first, then merge group plaintext.
                let mut h = entry
                    .envelope
                    .get("content_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if h.is_none() {
                    for v in entry.plaintext_per_group.values() {
                        if let Some(s) = v.get("content_hash").and_then(Value::as_str) {
                            h = Some(s.to_string());
                            break;
                        }
                    }
                }
                if let Some(h) = h {
                    if ts >= last_ts {
                        last_ts = ts;
                        last_hash = Some(h);
                    }
                }
            }
        }
        last_hash
    }

    /// Emit `tn.agents.policy_published` iff the active policy file's
    /// content_hash differs from the last published one in the log (or no
    /// prior event exists). No-op when no policy doc is loaded.
    pub(crate) fn maybe_emit_policy_published(&self) -> Result<()> {
        let Some(doc) = &self.agent_policies else {
            return Ok(());
        };
        if self.last_policy_published_hash().as_deref() == Some(doc.content_hash.as_str()) {
            return Ok(());
        }
        let mut fields = Map::new();
        fields.insert("policy_uri".into(), Value::String(doc.path.clone()));
        fields.insert("version".into(), Value::String(doc.version.clone()));
        fields.insert(
            "content_hash".into(),
            Value::String(doc.content_hash.clone()),
        );
        let event_types: Vec<Value> = doc
            .templates
            .keys()
            .map(|k| Value::String(k.clone()))
            .collect();
        fields.insert("event_types_covered".into(), Value::Array(event_types));
        fields.insert("policy_text".into(), Value::String(doc.body.clone()));
        self.emit("info", "tn.agents.policy_published", fields)?;
        Ok(())
    }

    /// Resolve the per-event file path for a `tn.*` event when
    /// `protocol_events_location` is a template string.
    ///
    /// Supported placeholders (mirrors `tn/config.py::resolve_protocol_events_path`):
    /// `{event_type}`, `{event_class}` (second dotted segment),
    /// `{yaml_dir}`, `{ceremony_id}`, `{did}`, `{date}` (UTC YYYY-MM-DD).
    fn resolve_pel(&self, event_type: &str) -> PathBuf {
        let tmpl = &self.cfg.ceremony.protocol_events_location;
        if tmpl == "main_log" {
            return self.log_path.clone();
        }
        // First dotted segment. Matches `python/tn/config.py::
        // resolve_path_template` (which uses `event_type.split(".")[0]`)
        // and `path_template.rs` (`event_type.split('.').next()`).
        let event_class = event_type.split('.').next().unwrap_or("unknown");
        let date_fmt = time::macros::format_description!("[year]-[month]-[day]");
        let date = OffsetDateTime::now_utc()
            .format(&date_fmt)
            .unwrap_or_else(|_| "1970-01-01".to_string());
        let yaml_dir_path = self
            .yaml_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let yaml_dir = yaml_dir_path.to_string_lossy().into_owned();
        let filled = tmpl
            .replace("{event_type}", event_type)
            .replace("{event_class}", event_class)
            .replace("{date}", &date)
            .replace("{yaml_dir}", &yaml_dir)
            .replace("{ceremony_id}", &self.cfg.ceremony.id)
            .replace("{did}", self.device.did());
        // Mirror Python's tn/config.py::resolve_protocol_events_path: a
        // template that resolves to a relative path is anchored at the
        // yaml's parent directory, NOT the process cwd. Without this
        // anchor, the publisher subprocess inherits its caller's cwd and
        // admin events end up in completely the wrong tree (e.g. the
        // FastAPI server's working dir instead of the per-publisher
        // ceremony dir).
        let p = PathBuf::from(filled);
        if is_absolute_xplat_path(&p) {
            p
        } else {
            yaml_dir_path.join(p)
        }
    }
}
