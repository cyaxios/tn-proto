//! Ceremony construction: `init` / `init_with_storage` /
//! `init_with_options` / `ephemeral`. Split out of `runtime.rs`; this is
//! one of `Runtime`'s impl blocks.

use super::*;

impl Runtime {
    /// Load a ceremony from `yaml_path` and return a ready-to-use Runtime.
    ///
    /// Native filesystem-backed factory. Internally delegates to
    /// [`Runtime::init_with_storage`] passing an `FsStorage` so the
    /// two paths share a single body. Use `init_with_storage`
    /// directly when you need an injected storage backend (wasm,
    /// tests, in-memory sandboxes).
    pub fn init(yaml_path: &Path) -> Result<Self> {
        crate::perf::init_from_env();
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::FsStorage::new());
        Self::init_with_storage(yaml_path, storage)
    }

    /// Load a ceremony with a caller-supplied [`Storage`] backend.
    ///
    /// Thin wrapper over [`Runtime::init_with_options`] using
    /// `RuntimeInitOptions::default()`. See that method for the full
    /// docstring.
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
    /// the same backend. **Today (Phase 7 landing) only the
    /// load-bearing reads inside `init` consult the storage; later
    /// phases fan it out across the rest of `Runtime`. See the
    /// `storage` field comment for the migration status.**
    ///
    /// `yaml_path` is read via `storage.read_bytes`; on wasm with a
    /// `JsStorageAdapter` that means the JS callback is invoked.
    ///
    /// `opts` lets the caller suppress side-effects that are
    /// inappropriate when the SDK has already initialized the
    /// ceremony out-of-band — see [`RuntimeInitOptions`].
    ///
    /// [`Storage`]: crate::storage::Storage
    #[allow(clippy::too_many_lines)]
    // cognitive_complexity: this fn intentionally holds the
    // ceremony-mint vs ceremony-load invariant in one place — see the
    // comment above. Splitting helpers would scatter the "what state
    // must be coherent before we hand back a Runtime" check across
    // call sites where it's easy to miss in review.
    #[allow(clippy::cognitive_complexity)]
    pub fn init_with_options(
        yaml_path: &Path,
        storage: Arc<dyn crate::storage::Storage>,
        opts: RuntimeInitOptions,
    ) -> Result<Self> {
        // Call site 1: yaml read. Routes through Storage so a wasm
        // `JsStorageAdapter` can satisfy the request from its JS-side
        // callback rather than `std::fs::read_to_string`.
        let yaml_bytes = storage.read_bytes(yaml_path).map_err(Error::Io)?;
        let yaml_str = std::str::from_utf8(&yaml_bytes).map_err(|e| {
            Error::InvalidConfig(format!("yaml is not valid UTF-8: {e}"))
        })?;
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

        let mut groups: BTreeMap<String, Arc<RwLock<GroupState>>> = BTreeMap::new();
        let mut btn_admin: BTreeMap<String, Arc<Mutex<BtnPublisherCipher>>> = BTreeMap::new();
        let mut btn_mykit: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();

        for (name, spec) in &cfg.groups {
            let index_key = crate::indexing::derive_group_index_key(
                &master_index_key,
                &cfg.ceremony.id,
                name,
                spec.index_epoch,
            )?;
            // Call site 4: cipher construction reads `<group>.btn.state`
            // and `<group>.btn.mykit` through storage.
            let (cipher, maybe_pub_cipher, mykit_bytes) =
                build_cipher_with_admin_with_storage(spec, &keystore, name, &storage)?;
            let hmac_template =
                crate::indexing::build_hmac_template(&index_key)?;
            groups.insert(
                name.clone(),
                Arc::new(RwLock::new(GroupState {
                    cipher,
                    index_key,
                    hmac_template,
                })),
            );
            if let Some(pub_cipher) = maybe_pub_cipher {
                btn_admin.insert(name.clone(), Arc::new(Mutex::new(pub_cipher)));
            }
            btn_mykit.insert(name.clone(), mykit_bytes);
        }

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

        // When protocol_events_location routes tn.* events to a separate file,
        // tn.ceremony.init never touches the main log. Check that file too.
        if !saw_ceremony_init && cfg.ceremony.protocol_events_location != "main_log" {
            let pel = resolve_pel_static(
                &cfg.ceremony.protocol_events_location,
                &yaml_dir,
                &cfg.ceremony.id,
                device.did(),
            );
            saw_ceremony_init = scan_for_ceremony_init(&pel, &storage)?;
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
        let pel_writer = {
            let pel_raw = &cfg.ceremony.protocol_events_location;
            if pel_raw == "main_log" {
                match &log_writer {
                    crate::log_file::LogWriters::Literal { path, writer } => {
                        crate::log_file::LogWriters::Literal {
                            path: path.clone(),
                            writer: writer.clone(),
                        }
                    }
                    crate::log_file::LogWriters::Templated { template, storage: stor, .. } => {
                        crate::log_file::LogWriters::Templated {
                            template: template.clone(),
                            storage: Arc::clone(stor),
                            writers: Mutex::new(std::collections::HashMap::new()),
                        }
                    }
                }
            } else {
                let pel_template = crate::path_template::PathTemplate::parse(
                    pel_raw,
                    &yaml_dir,
                    &cfg.ceremony.id,
                    device.did(),
                )?;
                if pel_template.is_templated() {
                    crate::log_file::LogWriters::Templated {
                        template: pel_template,
                        storage: Arc::clone(&storage),
                        writers: Mutex::new(std::collections::HashMap::new()),
                    }
                } else {
                    let path = pel_template.render("", "");
                    let writer = LogFileWriter::open(&path, Arc::clone(&storage))?;
                    crate::log_file::LogWriters::Literal {
                        path,
                        writer: Arc::new(Mutex::new(writer)),
                    }
                }
            }
        };

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
        let stdout_entry = rt
            .cfg
            .handlers
            .iter()
            .find(|h| h.get("kind").and_then(|v| v.as_str()) == Some("stdout"));
        let yaml_silences_stdout = !rt.cfg.handlers.is_empty() && stdout_entry.is_none();
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
            rt.add_handler(Arc::new(crate::handlers::StdoutHandler::with_format_and_filter(
                format,
                crate::handlers::spec::FilterSpec::default(),
            )));
        }

        // Honor an optional yaml `ceremony.log_level` so operators can
        // bake the threshold into config (AVL J3.2). Programmatic
        // `Runtime::set_level` calls are sticky across re-inits in the
        // same process, so only apply the yaml value when the threshold
        // is still at the floor default (DEBUG).
        if !rt.cfg.ceremony.log_level.is_empty()
            && LOG_LEVEL_THRESHOLD.load(Ordering::Relaxed) == log_level::DEBUG
        {
            // Best-effort: bad level names are logged + ignored so init
            // doesn't fail on a stale yaml field.
            if let Err(e) = Runtime::set_level(&rt.cfg.ceremony.log_level) {
                log::warn!(
                    "ceremony.log_level={:?} ignored: {e}",
                    rt.cfg.ceremony.log_level
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
            init_fields.insert("ceremony_id".into(), serde_json::json!(rt.cfg.ceremony.id));
            init_fields.insert("cipher".into(), serde_json::json!(rt.cfg.ceremony.cipher));
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
            if let Err(e) = rt.emit("info", "tn.ceremony.init", init_fields) {
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
            if let Err(e) = rt.maybe_emit_policy_published() {
                log::warn!("tn.agents.policy_published emit failed: {e}");
            }
        }

        Ok(rt)
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
    pub fn ephemeral() -> Result<Self> {
        let td = tempfile::Builder::new()
            .prefix("tn-ephemeral-")
            .tempdir()
            .map_err(Error::Io)?;
        let yaml_path = td.path().join("tn.yaml");
        write_fresh_btn_ceremony(td.path()).map_err(Error::Io)?;

        let mut rt = Self::init(&yaml_path)?;
        rt.owned_tempdir = Some(td);
        Ok(rt)
    }
}
