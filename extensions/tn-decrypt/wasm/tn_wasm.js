/* @ts-self-types="./tn_wasm.d.ts" */

/**
 * Publisher-side btn state.
 *
 * Wraps `tn_btn::PublisherState`. The constructor is equivalent to
 * `BtnPublisher.new(seed)` in Python: if `seed` is 32 bytes, the
 * publisher is deterministic; otherwise a random seed is generated.
 *
 * All mutating operations (`mint`, `revokeByLeaf`, `revokeKit`) change
 * internal state. Persist via `toBytes()` / restore via
 * `BtnPublisher.fromBytes()`.
 */
export class BtnPublisher {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BtnPublisher.prototype);
        obj.__wbg_ptr = ptr;
        BtnPublisherFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BtnPublisherFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_btnpublisher_free(ptr, 0);
    }
    /**
     * Encrypt `plaintext` for all currently-active readers. Returns
     * serialized ciphertext bytes.
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    encrypt(plaintext) {
        const ptr0 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.btnpublisher_encrypt(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * Current epoch counter.
     * @returns {number}
     */
    get epoch() {
        const ret = wasm.btnpublisher_epoch(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Restore a publisher state from bytes previously produced by
     * [`Self::to_bytes`].
     * @param {Uint8Array} bytes
     * @returns {BtnPublisher}
     */
    static fromBytes(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.btnpublisher_fromBytes(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BtnPublisher.__wrap(ret[0]);
    }
    /**
     * Number of currently-active reader kits.
     * @returns {number}
     */
    issuedCount() {
        const ret = wasm.btnpublisher_issuedCount(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Maximum readers this publisher can ever mint.
     * @returns {bigint}
     */
    maxLeaves() {
        const ret = wasm.btnpublisher_maxLeaves(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Mint a fresh reader kit. Returns its wire bytes (tnpkg-equivalent).
     * @returns {Uint8Array}
     */
    mint() {
        const ret = wasm.btnpublisher_mint(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Create a publisher. Pass `null` for a random seed, or a 32-byte
     * `Uint8Array` for a deterministic one.
     * @param {Uint8Array | null} [seed]
     */
    constructor(seed) {
        var ptr0 = isLikeNone(seed) ? 0 : passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.btnpublisher_new(ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        BtnPublisherFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * 32-byte publisher identifier. Stable for the lifetime of this state.
     * @returns {Uint8Array}
     */
    publisherId() {
        const ret = wasm.btnpublisher_publisherId(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Revoke a reader by leaf index. Idempotent.
     * @param {bigint} leaf
     */
    revokeByLeaf(leaf) {
        const ret = wasm.btnpublisher_revokeByLeaf(this.__wbg_ptr, leaf);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Revoke a reader by its kit bytes. Idempotent.
     * @param {Uint8Array} kit_bytes
     */
    revokeKit(kit_bytes) {
        const ptr0 = passArray8ToWasm0(kit_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.btnpublisher_revokeKit(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Number of revoked reader kits.
     * @returns {number}
     */
    revokedCount() {
        const ret = wasm.btnpublisher_revokedCount(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Serialize this publisher state for persistence. Treat as secret.
     * @returns {Uint8Array}
     */
    toBytes() {
        const ret = wasm.btnpublisher_toBytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Tree height for this build.
     * @returns {number}
     */
    treeHeight() {
        const ret = wasm.btnpublisher_treeHeight(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) BtnPublisher.prototype[Symbol.dispose] = BtnPublisher.prototype.free;

/**
 * JS-side wrapper around a single `tn-core` `Runtime` instance.
 *
 * Owns an `Arc<Runtime>` so the JS handle can be cloned-by-reference
 * in the future without forcing a `Runtime` copy. `Drop` releases the
 * shared reference; `close()` exists for callers that want an explicit
 * flush + a `Result` they can await on.
 */
export class WasmRuntime {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmRuntime.prototype);
        obj.__wbg_ptr = ptr;
        WasmRuntimeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRuntimeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmruntime_free(ptr, 0);
    }
    /**
     * Register a JS-supplied handler. Subsequent emits fan out
     * through it (subject to its `accepts` filter, if any).
     *
     * `callbacks` is a JS object: `{ name: string, emit: fn,
     * accepts?: fn, close?: fn }`. See `JsHandler::from_js` for the
     * full contract.
     * @param {any} callbacks
     */
    addHandler(callbacks) {
        const ret = wasm.wasmruntime_addHandler(this.__wbg_ptr, callbacks);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Mint kits for `runtimeDid` across the requested groups + the
     * reserved `tn.agents` group, then export a `kit_bundle` `.tnpkg`
     * at `outPath`. Optional `label` writes a sidecar `.label` file
     * next to the bundle (best-effort).
     *
     * `groups` is a JS array of strings; entries that aren't strings
     * are silently dropped. Returns the absolute bundle path.
     * Mirrors PyO3 `admin_add_agent_runtime`.
     * @param {string} runtime_did
     * @param {any[]} groups
     * @param {string} out_path
     * @param {string | null} [label]
     * @returns {string}
     */
    adminAddAgentRuntime(runtime_did, groups, out_path, label) {
        let deferred6_0;
        let deferred6_1;
        try {
            const ptr0 = passStringToWasm0(runtime_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(groups, wasm.__wbindgen_malloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(out_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(label) ? 0 : passStringToWasm0(label, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len3 = WASM_VECTOR_LEN;
            const ret = wasm.wasmruntime_adminAddAgentRuntime(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
            var ptr5 = ret[0];
            var len5 = ret[1];
            if (ret[3]) {
                ptr5 = 0; len5 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred6_0 = ptr5;
            deferred6_1 = len5;
            return getStringFromWasm0(ptr5, len5);
        } finally {
            wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
        }
    }
    /**
     * Mint a fresh btn reader kit for `group`, write it to
     * `outPath`, persist the updated publisher state, and return the
     * new recipient's leaf index.
     *
     * Optional `recipientDid` (`did:key:…`) attaches identity to the
     * `tn.recipient.added` attested event the publisher emits as a
     * side-effect. Mirrors PyO3 `add_recipient`.
     * @param {string} group
     * @param {string} out_path
     * @param {string | null} [recipient_did]
     * @returns {number}
     */
    adminAddRecipient(group, out_path, recipient_did) {
        const ptr0 = passStringToWasm0(group, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(out_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(recipient_did) ? 0 : passStringToWasm0(recipient_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_adminAddRecipient(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * Revoke the recipient at `leafIndex` in `group`. Persists the
     * updated state and emits `tn.recipient.revoked`. Mirrors PyO3
     * `revoke_recipient`. Accepts the leaf index as a JS `number`
     * (we widen to `u64` for `tn-core`).
     * @param {string} group
     * @param {number} leaf_index
     */
    adminRevokeRecipient(group, leaf_index) {
        const ptr0 = passStringToWasm0(group, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_adminRevokeRecipient(this.__wbg_ptr, ptr0, len0, leaf_index);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Number of recipients currently marked revoked in `group`'s
     * publisher state. Mirrors PyO3 `revoked_count`. Returned as a
     * JS `number`.
     * @param {string} group
     * @returns {number}
     */
    adminRevokedCount(group) {
        const ptr0 = passStringToWasm0(group, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_adminRevokedCount(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] >>> 0;
    }
    /**
     * Replay the log through the admin reducer and return the full
     * `AdminState` as a plain JS object. `group` is optional — pass
     * `null` for the all-groups view, a string to scope to one
     * group's rows. Mirrors PyO3 `admin_state`.
     * @param {string | null} [group]
     * @returns {any}
     */
    adminState(group) {
        var ptr0 = isLikeNone(group) ? 0 : passStringToWasm0(group, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_adminState(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Mint a fresh kit for `recipientDid` across one or more groups
     * and bundle them into a single `.tnpkg` at `outPath`. `groups`
     * is optional — pass `null`/`undefined` to bundle every non-
     * internal group declared in the active ceremony.
     *
     * Mirrors PyO3 `bundle_for_recipient` and Python
     * `tn.bundle_for_recipient`. Returns the absolute bundle path.
     * @param {string} recipient_did
     * @param {string} out_path
     * @param {any[] | null} [groups]
     * @returns {string}
     */
    bundleForRecipient(recipient_did, out_path, groups) {
        let deferred5_0;
        let deferred5_1;
        try {
            const ptr0 = passStringToWasm0(recipient_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(out_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(groups) ? 0 : passArrayJsValueToWasm0(groups, wasm.__wbindgen_malloc);
            var len2 = WASM_VECTOR_LEN;
            const ret = wasm.wasmruntime_bundleForRecipient(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var ptr4 = ret[0];
            var len4 = ret[1];
            if (ret[3]) {
                ptr4 = 0; len4 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred5_0 = ptr4;
            deferred5_1 = len4;
            return getStringFromWasm0(ptr4, len4);
        } finally {
            wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
        }
    }
    /**
     * Explicit flush + close.
     *
     * Consumes `self`. Optional — the `Runtime`'s own `Drop` impl
     * flushes OS file buffers via `File::Drop`. Use `close()` when
     * you want to surface a flush error to JS rather than let it slip
     * past.
     *
     * Implementation note: we can only call `Runtime::close(self)`
     * when we hold the unique owner of the `Arc`. If JS code clones
     * the handle (it can't today, but it might in a later phase),
     * the unwrap falls back to a best-effort drop without surfacing
     * flush errors.
     */
    close() {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.wasmruntime_close(ptr);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * DEBUG-level attested event.
     * @param {string} event_type
     * @param {any} fields
     */
    debug(event_type, fields) {
        const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_debug(this.__wbg_ptr, ptr0, len0, fields);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * This runtime's publisher DID (`did:key:z…`).
     * @returns {string}
     */
    did() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmruntime_did(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Emit one envelope at `level` for `eventType` with `fields`.
     *
     * `fields` must be a JS object that maps to a JSON object — keys
     * are strings, values are anything `JSON.stringify` accepts. The
     * envelope is signed (or not) per the ceremony yaml; use
     * `emitOverrideSign` (Phase 3) for per-call control.
     *
     * Returns `undefined` on success; throws on schema violations,
     * I/O failures, or a non-object `fields` value. (The richer
     * "returns the envelope ndjson line on success, `None` if the
     * log-level threshold filtered it" shape that the PyO3 binding
     * exposes lands in Phase 3 alongside the other emit variants.)
     * @param {string} level
     * @param {string} event_type
     * @param {any} fields
     */
    emit(level, event_type, fields) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_emit(this.__wbg_ptr, ptr0, len0, ptr1, len1, fields);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Emit with an explicit `sign` override.
     *
     * `None` (JS `null`/`undefined`) keeps the ceremony default;
     * `Some(true)` forces a signature; `Some(false)` skips it.
     * @param {string} level
     * @param {string} event_type
     * @param {any} fields
     * @param {boolean | null} [sign]
     */
    emitOverrideSign(level, event_type, fields, sign) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_emitOverrideSign(this.__wbg_ptr, ptr0, len0, ptr1, len1, fields, isLikeNone(sign) ? 0xFFFFFF : sign ? 1 : 0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Full-control emit that returns the canonical envelope NDJSON line
     * (or `undefined` when the log-level threshold filtered the emit).
     *
     * Mirrors the PyO3 binding's line-returning emit. The host (TS
     * `NodeRuntime`) parses the returned line to synthesize the
     * `EmitReceipt` directly, instead of reading the row back off the
     * log. That read-back breaks for templated `logs.path` (e.g.
     * `./logs/{event_id}.ndjson`) where the just-written row lives in a
     * per-event file, not the single main log — the line is the source
     * of truth regardless of where it was written.
     * @param {string} level
     * @param {string} event_type
     * @param {any} fields
     * @param {string | null} [timestamp]
     * @param {string | null} [event_id]
     * @param {boolean | null} [sign]
     * @returns {string | undefined}
     */
    emitReturningLine(level, event_type, fields, timestamp, event_id, sign) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(timestamp) ? 0 : passStringToWasm0(timestamp, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(event_id) ? 0 : passStringToWasm0(event_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_emitReturningLine(this.__wbg_ptr, ptr0, len0, ptr1, len1, fields, ptr2, len2, ptr3, len3, isLikeNone(sign) ? 0xFFFFFF : sign ? 1 : 0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        let v5;
        if (ret[0] !== 0) {
            v5 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v5;
    }
    /**
     * Emit with explicit `timestamp` / `event_id` overrides.
     *
     * `null`/`undefined` for either argument falls back to the
     * runtime's defaults (`OffsetDateTime::now_utc()` and a fresh
     * UUID). Signing follows the ceremony's yaml `sign` flag — use
     * `emitWithOverrideSign` for per-call signing control.
     * @param {string} level
     * @param {string} event_type
     * @param {any} fields
     * @param {string | null} [timestamp]
     * @param {string | null} [event_id]
     */
    emitWith(level, event_type, fields, timestamp, event_id) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(timestamp) ? 0 : passStringToWasm0(timestamp, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(event_id) ? 0 : passStringToWasm0(event_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_emitWith(this.__wbg_ptr, ptr0, len0, ptr1, len1, fields, ptr2, len2, ptr3, len3);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Full-control emit: explicit timestamp, event_id, and sign override.
     * @param {string} level
     * @param {string} event_type
     * @param {any} fields
     * @param {string | null} [timestamp]
     * @param {string | null} [event_id]
     * @param {boolean | null} [sign]
     */
    emitWithOverrideSign(level, event_type, fields, timestamp, event_id, sign) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(timestamp) ? 0 : passStringToWasm0(timestamp, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(event_id) ? 0 : passStringToWasm0(event_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_emitWithOverrideSign(this.__wbg_ptr, ptr0, len0, ptr1, len1, fields, ptr2, len2, ptr3, len3, isLikeNone(sign) ? 0xFFFFFF : sign ? 1 : 0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * ERROR-level attested event.
     * @param {string} event_type
     * @param {any} fields
     */
    error(event_type, fields) {
        const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_error(this.__wbg_ptr, ptr0, len0, fields);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * The active threshold as a level name (or the numeric stringified
     * value when it doesn't match one of the four standard names).
     * @returns {string}
     */
    static getLevel() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmruntime_getLevel();
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Names of every group declared in the active ceremony yaml, in
     * `BTreeMap` (alphabetical) order — matches what
     * `Runtime::group_names` returns.
     * @returns {any[]}
     */
    groupNames() {
        const ret = wasm.wasmruntime_groupNames(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * INFO-level attested event.
     * @param {string} event_type
     * @param {any} fields
     */
    info(event_type, fields) {
        const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_info(this.__wbg_ptr, ptr0, len0, fields);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Load a ceremony from `yamlPath` using a JS-supplied storage
     * callbacks object.
     *
     * The `storage` argument must be a JS object with the property
     * shape documented in `crypto/tn-wasm/src/storage.rs` — `read`,
     * `write`, `append`, `exists`, `list`, `rename`, `remove`,
     * `createDirAll`, `casWrite` (synchronous function values).
     * Node consumers wrap `fs.*Sync` methods; future browser
     * consumers wrap an IndexedDB shim.
     *
     * Internally constructs a [`JsStorageAdapter`] around the
     * callbacks and hands it to `Runtime::init_with_storage`. Every
     * file read during init (yaml, device key, master index key,
     * per-group cipher state + kits, agents.md) goes through the
     * adapter. Subsequent emit / read / admin call sites still talk
     * to `std::fs::*` directly; finishing the migration is Phase 7
     * follow-up work documented in the storage abstraction's
     * `Storage` trait comment.
     *
     * Errors surface as `JsError` with the Rust `Display` message.
     * @param {string} yaml_path
     * @param {any} storage
     * @returns {WasmRuntime}
     */
    static init(yaml_path, storage) {
        const ptr0 = passStringToWasm0(yaml_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_init(ptr0, len0, storage);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmRuntime.__wrap(ret[0]);
    }
    /**
     * Like `init` but takes an `opts` object with extra knobs that
     * SDK wrappers need.
     *
     * Recognised keys on `opts`:
     * * `skipCeremonyInitEmit`: bool — when true, suppress the
     *   auto-emit of `tn.ceremony.init` even when the ceremony looks
     *   fresh. Used by the TS `NodeRuntime` so the lazy `attachWasm()`
     *   hop doesn't double-attest a ceremony the TS path has already
     *   wired up.
     *
     * Returns a fully-constructed [`WasmRuntime`]. Errors surface as
     * [`JsError`] with the Rust `Display` message.
     * @param {string} yaml_path
     * @param {any} storage
     * @param {any} opts
     * @returns {WasmRuntime}
     */
    static initWith(yaml_path, storage, opts) {
        const ptr0 = passStringToWasm0(yaml_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_initWith(ptr0, len0, storage, opts);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmRuntime.__wrap(ret[0]);
    }
    /**
     * True iff `level` would currently emit. Use as a guard for
     * expensive log-arg construction (mirrors Python's
     * `Logger.isEnabledFor`).
     * @param {string} level
     * @returns {boolean}
     */
    static isEnabledFor(level) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_isEnabledFor(ptr0, len0);
        return ret !== 0;
    }
    /**
     * Severity-less attested event (envelope carries `level: ""`).
     *
     * Bypasses the log-level threshold filter by design — this is the
     * "this is a fact" primitive whose semantics shouldn't depend on
     * the active level.
     * @param {string} event_type
     * @param {any} fields
     */
    log(event_type, fields) {
        const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_log(this.__wbg_ptr, ptr0, len0, fields);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Absolute path of the main ndjson log this runtime writes to.
     * @returns {string}
     */
    logPath() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmruntime_logPath(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Read every entry from the main log as flat JS objects.
     *
     * Matches the PyO3 `Runtime.read()` default shape: six envelope
     * basics (`timestamp`, `event_type`, `level`, `did`, `sequence`,
     * `event_id`) plus every readable group's decrypted fields
     * hoisted to the top level. Filtered to the current process's
     * `run_id` by default — to span every run use `readAllRuns`
     * (Phase 2).
     *
     * Returns `Entry[]` (a JS array of plain objects).
     * @returns {any}
     */
    read() {
        const ret = wasm.wasmruntime_read(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Like `read()` but returns entries from every run on disk (not
     * just the current process's `$TN_RUN_ID`). Use for audit /
     * compliance reports that span the whole log lifetime.
     *
     * Mirrors the PyO3 `Runtime.read_all_runs()` shape: same flat dicts
     * as `read()`, just unfiltered. Phase 2 surface per the wasm
     * widening plan.
     * @returns {any}
     */
    readAllRuns() {
        const ret = wasm.wasmruntime_readAllRuns(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Read all entries from an explicit `logPath` as `{envelope,
     * plaintext}` records (audit-grade shape). Mirrors PyO3
     * `read_raw(log_path=…)` / Python `tn.read_raw(log_path=…)` —
     * useful for cross-publisher reads where the caller absorbed a
     * foreign kit and wants to decrypt that party's log.
     *
     * Returns the same `{envelope, plaintext}` shape that `readRaw()`
     * produces; consumers who want the flat hoisted shape can post-
     * process or call `readWithVerify` once it grows a path arg.
     * @param {string} log_path
     * @returns {any}
     */
    readFrom(log_path) {
        const ptr0 = passStringToWasm0(log_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_readFrom(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * As [`Self::read_raw_with_validity_js`] but reads from an
     * explicit `logPath`. Mirrors Python
     * `tn.read_raw_with_validity(log_path=…)`.
     * @param {string} log_path
     * @returns {any}
     */
    readFromWithValidity(log_path) {
        const ptr0 = passStringToWasm0(log_path, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_readFromWithValidity(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Audit-grade read: returns one object per entry with the full
     * on-disk `envelope` (including `prev_hash` / `row_hash` /
     * `signature` / `groups`) plus a `plaintext` map of per-group
     * decrypted values. Mirrors PyO3 `Runtime.read_raw()` — key name is
     * `plaintext` (not the Rust field name `plaintext_per_group`) so
     * the JS surface matches Python.
     * @returns {any}
     */
    readRaw() {
        const ret = wasm.wasmruntime_readRaw(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Audit-grade read against the runtime's own log with explicit
     * per-row validity flags. Returns one object per entry:
     * `{envelope, plaintext, valid: {signature, row_hash, chain}}`.
     * Mirrors PyO3's `(ReadEntry, ValidFlags)` tuple — flattened into
     * a single dict for the JS surface so consumers don't need a
     * tuple shim. Mirrors Python `tn.read_raw_with_validity()`.
     * @returns {any}
     */
    readRawWithValidity() {
        const ret = wasm.wasmruntime_readRawWithValidity(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Like `read()` but adds a `_valid: {signature, row_hash, chain}`
     * block to each flat entry so callers can inspect verification
     * status without raising. Mirrors PyO3 `Runtime.read_with_verify()`.
     * @returns {any}
     */
    readWithVerify() {
        const ret = wasm.wasmruntime_readWithVerify(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Return the current recipient roster for `group` by replaying
     * the log. When `includeRevoked` is true, revoked recipients are
     * appended after the active ones. Mirrors PyO3 `recipients`.
     * Returns a JS array of plain objects (`{leafIndex, recipientDid,
     * mintedAt, kitSha256, revoked, revokedAt}`); the snake_case
     * field names from `RecipientEntry` survive intact through the
     * serde roundtrip.
     * @param {string} group
     * @param {boolean} include_revoked
     * @returns {any}
     */
    recipients(group, include_revoked) {
        const ptr0 = passStringToWasm0(group, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_recipients(this.__wbg_ptr, ptr0, len0, include_revoked);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Verified read (sig + row_hash + chain). On failure, behavior
     * follows `onInvalid`:
     *   - `"skip"` — drop the bad row, append a
     *     `tn.read.tampered_row_skipped` admin event (default).
     *   - `"raise"` — throw a JS error.
     *   - `"forensic"` — keep the row, attach `_valid` and
     *     `_invalid_reasons` markers.
     *
     * Each returned entry is a flat dict shaped like `read()`, plus an
     * optional `instructions` block when the caller holds the
     * `tn.agents` kit (mirroring PyO3 `Runtime.secure_read()`).
     * `_hidden_groups` / `_decrypt_errors` are surfaced as arrays when
     * non-empty.
     * @param {string} on_invalid
     * @returns {any}
     */
    secureRead(on_invalid) {
        const ptr0 = passStringToWasm0(on_invalid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_secureRead(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Set the process-wide log-level threshold by name. Accepts
     * "debug" / "info" / "warning" / "error" (case-insensitive,
     * "warn" aliases "warning"). Throws on unknown names.
     * @param {string} level
     */
    static setLevel(level) {
        const ptr0 = passStringToWasm0(level, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_setLevel(ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Set the process-wide threshold from a numeric value (10/20/
     * 30/40 etc.). Lets callers plug in custom severities without
     * the string map.
     * @param {number} level
     */
    static setLevelValue(level) {
        wasm.wasmruntime_setLevelValue(level);
    }
    /**
     * Emit a signed `tn.vault.linked` admin event recording that this
     * ceremony is paired with `vaultDid`'s `projectId`. Idempotent —
     * an active link to the same `(vault_did, project_id)` is a no-op.
     * Mirrors PyO3 `vault_link` and Python `tn.vault_link`.
     * @param {string} vault_did
     * @param {string} project_id
     */
    vaultLink(vault_did, project_id) {
        const ptr0 = passStringToWasm0(vault_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(project_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_vaultLink(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Emit a signed `tn.vault.unlinked` admin event recording that the
     * pairing between this ceremony and `vaultDid`'s `projectId` has
     * been severed. `reason` is an optional free-form string; pass
     * `null`/`undefined` to omit (the event will carry `reason: null`).
     * Mirrors PyO3 `vault_unlink` and Python `tn.vault_unlink`.
     * @param {string} vault_did
     * @param {string} project_id
     * @param {string | null} [reason]
     */
    vaultUnlink(vault_did, project_id, reason) {
        const ptr0 = passStringToWasm0(vault_did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(project_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(reason) ? 0 : passStringToWasm0(reason, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_vaultUnlink(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * WARNING-level attested event.
     * @param {string} event_type
     * @param {any} fields
     */
    warning(event_type, fields) {
        const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmruntime_warning(this.__wbg_ptr, ptr0, len0, fields);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) WasmRuntime.prototype[Symbol.dispose] = WasmRuntime.prototype.free;

/**
 * List the catalogued admin event kinds.
 *
 * Returns `[{event_type, sign, sync, schema: [[name, type], ...]}, ...]`.
 * Schema types are strings: `string`, `optional_string`, `int`,
 * `optional_int`, `iso8601`.
 * @returns {any}
 */
export function adminCatalogKinds() {
    const ret = wasm.adminCatalogKinds();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Reduce an envelope to a typed state delta.
 *
 * `envelope` is a JS object matching the flat ndjson envelope shape
 * (top-level `event_type`, `did`, plus the catalog's admin fields).
 *
 * Returns the JSON serialization of `StateDelta`, tagged with `kind`.
 *
 * Errors propagate as JS exceptions (`Error`) with the reducer's message.
 * @param {any} envelope
 * @returns {any}
 */
export function adminReduce(envelope) {
    const ret = wasm.adminReduce(envelope);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Validate that `fields` match the catalog schema for `eventType`.
 *
 * Throws on schema violation; returns `undefined` on success.
 * @param {string} event_type
 * @param {any} fields
 */
export function adminValidateEmit(event_type, fields) {
    const ptr0 = passStringToWasm0(event_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.adminValidateEmit(ptr0, len0, fields);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Extract the 32-byte publisher_id from a ciphertext.
 * @param {Uint8Array} ct_bytes
 * @returns {Uint8Array}
 */
export function btnCiphertextPublisherId(ct_bytes) {
    const ptr0 = passArray8ToWasm0(ct_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.btnCiphertextPublisherId(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Decrypt `ctBytes` with `kitBytes`. Returns plaintext bytes. Throws
 * on NotEntitled or malformed input.
 * @param {Uint8Array} kit_bytes
 * @param {Uint8Array} ct_bytes
 * @returns {Uint8Array}
 */
export function btnDecrypt(kit_bytes, ct_bytes) {
    const ptr0 = passArray8ToWasm0(kit_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(ct_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.btnDecrypt(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Extract the leaf index (u64) from a reader kit.
 * @param {Uint8Array} kit_bytes
 * @returns {bigint}
 */
export function btnKitLeaf(kit_bytes) {
    const ptr0 = passArray8ToWasm0(kit_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.btnKitLeaf(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return BigInt.asUintN(64, ret[0]);
}

/**
 * Extract the 32-byte publisher_id from a reader kit.
 * @param {Uint8Array} kit_bytes
 * @returns {Uint8Array}
 */
export function btnKitPublisherId(kit_bytes) {
    const ptr0 = passArray8ToWasm0(kit_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.btnKitPublisherId(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Max leaves constant.
 * @returns {bigint}
 */
export function btnMaxLeaves() {
    const ret = wasm.btnMaxLeaves();
    return BigInt.asUintN(64, ret);
}

/**
 * Tree height constant.
 * @returns {number}
 */
export function btnTreeHeight() {
    const ret = wasm.btnTreeHeight();
    return ret;
}

/**
 * Build an envelope ndjson line (9 mandatory fields, then public, then
 * group payloads), followed by a trailing `\n`.
 *
 * `input` shape:
 * ```json
 * {
 *   "device_identity": string, "timestamp": string, "event_id": string,
 *   "event_type": string, "level": string, "sequence": number,
 *   "prev_hash": string, "row_hash": string, "signature_b64": string,
 *   "public_fields": { [key]: value },
 *   "group_payloads": { [group]: { "ciphertext": "<b64>", "field_hashes": {...} } }
 * }
 * ```
 *
 * Public fields + group payloads preserve insertion order.
 * @param {any} input
 * @returns {string}
 */
export function buildEnvelope(input) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.buildEnvelope(input);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Serialize a JSON value to canonical bytes (sorted keys, no whitespace).
 *
 * Returns a `Uint8Array`. Byte-identical to
 * `tn.canonical.canonical_bytes` in Python.
 * @param {any} value
 * @returns {Uint8Array}
 */
export function canonicalBytes(value) {
    const ret = wasm.canonicalBytes(value);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Convenience: canonical bytes as a UTF-8 string. Callers who want the
 * raw bytes should use `canonicalBytes`. This variant is for `row_hash`
 * debugging in TS, which often wants a readable string.
 * @param {any} value
 * @returns {string}
 */
export function canonicalJson(value) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.canonicalJson(value);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Compute a row_hash.
 *
 * `input` is a JSON object with:
 * ```json
 * {
 *   "device_identity": string,
 *   "timestamp": string,
 *   "event_id": string,
 *   "event_type": string,
 *   "level": string,
 *   "prev_hash": string,
 *   "public_fields": { [key]: value },
 *   "groups": {
 *     [group_name]: {
 *       "ciphertext_b64": string,   // standard base64
 *       "field_hashes": { [field_name]: token_string }
 *     }
 *   }
 * }
 * ```
 *
 * Returns `"sha256:<64-hex>"`.
 * @param {any} input
 * @returns {string}
 */
export function computeRowHash(input) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.computeRowHash(input);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Encode a 32-byte Ed25519 public key as `did:key:z…`.
 * @param {Uint8Array} public_key
 * @returns {string}
 */
export function deriveDidKey(public_key) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.deriveDidKey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive the per-group HKDF index key from a 32-byte master.
 *
 * Info string: `b"tn-index:v1:" + ceremony + b":" + group + b":" + decimal(epoch)`.
 * Returns 32 bytes.
 * @param {Uint8Array} master
 * @param {string} ceremony_id
 * @param {string} group_name
 * @param {bigint} epoch
 * @returns {Uint8Array}
 */
export function deriveGroupIndexKey(master, ceremony_id, group_name, epoch) {
    const ptr0 = passArray8ToWasm0(master, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(ceremony_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(group_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.deriveGroupIndexKey(ptr0, len0, ptr1, len1, ptr2, len2, epoch);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Load a device key from its 32-byte Ed25519 seed.
 *
 * Returns `{ seed, publicKey, did }` matching `generateDeviceKey`.
 * @param {Uint8Array} seed
 * @returns {any}
 */
export function deviceKeyFromSeed(seed) {
    const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deviceKeyFromSeed(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Generate a fresh Ed25519 device key.
 *
 * Returns `{ seed: Uint8Array(32), publicKey: Uint8Array(32), did: string }`.
 * @returns {any}
 */
export function generateDeviceKey() {
    const ret = wasm.generateDeviceKey();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Compute the keyed equality token `"hmac-sha256:v1:<hex>"` for a
 * (field_name, value) pair under a 32-byte group index key.
 * @param {Uint8Array} group_index_key
 * @param {string} field_name
 * @param {any} value
 * @returns {string}
 */
export function indexToken(group_index_key, field_name, value) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(group_index_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(field_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.indexToken(ptr0, len0, ptr1, len1, value);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * True iff vector clock `a` dominates `b` on every `(did, event_type)`
 * coordinate.
 * @param {any} a
 * @param {any} b
 * @returns {boolean}
 */
export function manifestClockDominates(a, b) {
    const ret = wasm.manifestClockDominates(a, b);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Pointwise max of two vector clocks.
 * @param {any} a
 * @param {any} b
 * @returns {any}
 */
export function manifestClockMerge(a, b) {
    const ret = wasm.manifestClockMerge(a, b);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * List the manifest kinds recognized by the Rust core.
 * @returns {any}
 */
export function manifestKnownKinds() {
    const ret = wasm.manifestKnownKinds();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Canonical signing bytes for a manifest, with `manifest_signature_b64`
 * stripped by the Rust core.
 * @param {any} manifest_doc
 * @returns {Uint8Array}
 */
export function manifestSigningBytes(manifest_doc) {
    const ret = wasm.manifestSigningBytes(manifest_doc);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Normalize a manifest wire dictionary through the Rust manifest parser.
 * @param {any} manifest_doc
 * @returns {any}
 */
export function manifestToWireDict(manifest_doc) {
    const ret = wasm.manifestToWireDict(manifest_doc);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Return true iff the manifest signature verifies against
 * `publisher_identity`.
 * @param {any} manifest_doc
 * @returns {boolean}
 */
export function manifestVerifySignature(manifest_doc) {
    const ret = wasm.manifestVerifySignature(manifest_doc);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Sign `message` with the 32-byte Ed25519 seed. Returns a 64-byte
 * signature.
 * @param {Uint8Array} seed
 * @param {Uint8Array} message
 * @returns {Uint8Array}
 */
export function signMessage(seed, message) {
    const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.signMessage(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * URL-safe base64 (no padding) encoding of a signature. Mirror of
 * `tn.signing.signature_b64`.
 * @param {Uint8Array} sig
 * @returns {string}
 */
export function signatureB64(sig) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(sig, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signatureB64(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Decode a URL-safe-no-padding base64 signature.
 * @param {string} s
 * @returns {Uint8Array}
 */
export function signatureFromB64(s) {
    const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.signatureFromB64(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Read a `.tnpkg` archive from bytes.
 *
 * Returns `{ manifest, body }`, where `body` is an array of
 * `{ name, data: Uint8Array }` entries. Signature verification is a separate
 * manifest operation, matching Rust/Python.
 * @param {Uint8Array} bytes
 * @returns {any}
 */
export function tnpkgReadBytes(bytes) {
    const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.tnpkgReadBytes(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Write a `.tnpkg` archive to bytes from a manifest wire dictionary and
 * body entries (`[{ name, data: Uint8Array }, ...]`).
 * @param {any} manifest_doc
 * @param {any} entries
 * @returns {Uint8Array}
 */
export function tnpkgWriteBytes(manifest_doc, entries) {
    const ret = wasm.tnpkgWriteBytes(manifest_doc, entries);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Verify a signature against an Ed25519 `did:key:z…` identity.
 *
 * Returns `false` for non-Ed25519 DIDs (secp256k1 verify deferred to
 * match the Rust core policy), `true` only if the signature is valid.
 * @param {string} did
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @returns {boolean}
 */
export function verifyDid(did, message, signature) {
    const ptr0 = passStringToWasm0(did, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verifyDid(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

/**
 * Zero-initialized prev_hash used for the first row in a new
 * event_type chain.
 * @returns {string}
 */
export function zeroHash() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.zeroHash();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_960c155d3d49e4c2: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_boolean_get_6ea149f0a8dcc5ff: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_ab4b34d23d6778bd: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_3baa9db1a987f47d: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_52ff4ec04186736f: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_object_63322ec0cd6ea4ef: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_6df3bf7ef1164ed3: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_29a43b4d42920abd: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_7ed5322991caaec5: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_6b64449b9b9ed33c: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_14b169f759b26747: function() { return handleError(function (arg0, arg1) {
            const ret = arg0.call(arg1);
            return ret;
        }, arguments); },
        __wbg_call_86e39d65afc3d9db: function() { return handleError(function (arg0, arg1, arg2, arg3, arg4) {
            const ret = arg0.call(arg1, arg2, arg3, arg4);
            return ret;
        }, arguments); },
        __wbg_call_a24592a6f349a97e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_call_bb28efe6b2f55b86: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.call(arg1, arg2, arg3);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_from_0dbf29f09e7fb200: function(arg0) {
            const ret = Array.from(arg0);
            return ret;
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getRandomValues_ef12552bf5acd2fe: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getTime_da7c55f52b71e8c6: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_get_6011fa3a58f61074: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_get_8360291721e2339f: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_get_unchecked_17f53dad852b9588: function(arg0, arg1) {
            const ret = arg0[arg1 >>> 0];
            return ret;
        },
        __wbg_instanceof_Uint8Array_152ba1f289edcf3f: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_isArray_c3109d14ffc06469: function(arg0) {
            const ret = Array.isArray(arg0);
            return ret;
        },
        __wbg_length_3d4ecd04bd8d22f1: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_length_9f1775224cf1d815: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_0_4d657201ced14de3: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_0c7403db6e782f19: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_682678e2f47e32bc: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_aa8d0fa9762c29bd: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_from_slice_b5ea43e23f6008c0: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_with_length_8c854e41ea4dae9b: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_0cce8c6798af1870: function() { return handleError(function () {
            const ret = Date.now();
            return ret;
        }, arguments); },
        __wbg_parse_1bbc9c053611d0a7: function() { return handleError(function (arg0, arg1) {
            const ret = JSON.parse(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_a6b02eb00b0f4ce2: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_push_471a5b068a5295f6: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_set_022bee52d0b05b19: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_8cfadc87a297ca02: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_602256ae5c8f42cf: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_e445c1c7484aecc3: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f20e8576ef1e0f17: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_stringify_91082ed7a5a5769e: function() { return handleError(function (arg0) {
            const ret = JSON.stringify(arg0);
            return ret;
        }, arguments); },
        __wbg_subarray_f8ca46a25b1f5e0d: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./tn_wasm_bg.js": import0,
    };
}

const BtnPublisherFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_btnpublisher_free(ptr >>> 0, 1));
const WasmRuntimeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmruntime_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('tn_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
