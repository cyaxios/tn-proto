// TN log entry — the typed return value of `Tn.read()` and `Tn.watch()`
// (default mode). Replaces the legacy `Record<string, unknown>` flat
// shape. User-emitted kwargs land in `Entry.fields`; envelope and chain
// plumbing surface as typed attributes the IDE autocompletes.
//
// Mirrors Python's `tn._entry.Entry`. The wire format on disk is unchanged
// — this class is purely about how entries surface to caller code.
//
// Pass `raw: true` to `Tn.read` / `Tn.watch` to skip Entry construction
// and yield the on-disk envelope dict instead.
// Node's `util.inspect.custom` is just a well-known symbol —
// `Symbol.for("nodejs.util.inspect.custom")`. Reach for the symbol
// directly so this module loads in browsers without pulling in
// `node:util`. Node still recognizes the method and uses it for
// `console.log` pretty-printing; browsers ignore it harmlessly.
const NODE_INSPECT_CUSTOM = Symbol.for("nodejs.util.inspect.custom");
/**
 * Raised when a `Tn.read({verify: true | "raise"})` iterator hits an
 * entry that fails one or more of (signature, row_hash, chain).
 *
 * Use `verify: "skip"` to drop invalid rows silently and emit a
 * `tn.read.tampered_row_skipped` admin event, or omit `verify` (default
 * `false`) to read without integrity checks.
 */
export class VerifyError extends Error {
    sequence;
    event_type;
    failed_checks;
    constructor(sequence, event_type, failed_checks) {
        super(`entry seq=${sequence} event=${JSON.stringify(event_type)} failed: ` +
            failed_checks.join(", "));
        this.name = "VerifyError";
        this.sequence = sequence;
        this.event_type = event_type;
        this.failed_checks = [...failed_checks];
    }
}
const ENVELOPE_BASICS = new Set([
    "event_type",
    "timestamp",
    "level",
    "did",
    "sequence",
    "event_id",
    "run_id",
    "prev_hash",
    "row_hash",
    "signature",
    "message",
]);
const ENVELOPE_KEYS_FROM_FLAT = new Set([
    "event_type",
    "timestamp",
    "level",
    "message",
    "did",
    "event_id",
    "sequence",
    "run_id",
    "prev_hash",
    "row_hash",
    "signature",
]);
function _coerceTimestamp(v) {
    if (v instanceof Date)
        return v;
    if (typeof v === "string")
        return new Date(v);
    if (typeof v === "number")
        return new Date(v);
    return new Date(NaN);
}
function _formatHHMMSSmmm(ts) {
    // Python: timestamp.astimezone(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    // Format as UTC with millisecond precision.
    const hh = String(ts.getUTCHours()).padStart(2, "0");
    const mm = String(ts.getUTCMinutes()).padStart(2, "0");
    const ss = String(ts.getUTCSeconds()).padStart(2, "0");
    const ms = String(ts.getUTCMilliseconds()).padStart(3, "0");
    return `${hh}:${mm}:${ss}.${ms}`;
}
function _pyRepr(v) {
    // Matches Python repr() for the common types that show up in TN
    // payloads: strings get single-quoted, numbers/bools/null print
    // unadorned, anything else falls back to JSON.
    if (typeof v === "string") {
        return "'" + v.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
    }
    if (typeof v === "number" || typeof v === "bigint" || typeof v === "boolean") {
        if (typeof v === "boolean")
            return v ? "True" : "False";
        return String(v);
    }
    if (v === null)
        return "None";
    if (v === undefined)
        return "None";
    try {
        return JSON.stringify(v);
    }
    catch {
        return String(v);
    }
}
/** One TN log entry. Default return type for `Tn.read()` / `Tn.watch()`. */
export class Entry {
    // Essentials — user-visible, typed
    event_type;
    timestamp;
    level;
    message;
    // User payload — emitted kwargs live here
    fields;
    // Chain / authorship — typed, always present
    did;
    event_id;
    sequence;
    run_id;
    prev_hash;
    row_hash;
    signature;
    // Read-time signal — populated when reading as recipient and some
    // group ciphertext blocks were present in the envelope but the
    // caller's keystore couldn't decrypt them.
    hidden_groups;
    constructor(init) {
        this.event_type = init.event_type;
        this.timestamp = init.timestamp;
        this.level = init.level;
        this.message = init.message ?? null;
        this.fields = init.fields ?? {};
        this.did = init.did;
        this.event_id = init.event_id;
        this.sequence = init.sequence;
        this.run_id = init.run_id;
        this.prev_hash = init.prev_hash;
        this.row_hash = init.row_hash;
        this.signature = init.signature;
        this.hidden_groups = init.hidden_groups ?? [];
    }
    // -----------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------
    /**
     * Build an Entry from a raw `{envelope, plaintext, valid}` triple as
     * produced by the reader's parse path.
     *
     * - Envelope fields go to typed attributes.
     * - Decrypted plaintext from every group (alphabetical, last-write-wins
     *   on collision) merges into `fields`.
     * - Group blocks the caller couldn't decrypt land in `hidden_groups`.
     */
    static fromRaw(raw) {
        const env = raw.envelope;
        const plaintext = (raw.plaintext ?? {});
        const fields = {};
        const hidden = [];
        // Merge group plaintexts in alphabetical order (last-write-wins).
        const groupNames = Object.keys(plaintext).sort();
        for (const gname of groupNames) {
            const body = plaintext[gname];
            if (body === null || typeof body !== "object" || Array.isArray(body))
                continue;
            const b = body;
            if (b["$decrypt_error"] === true) {
                hidden.push(gname);
                continue;
            }
            if (b["$no_read_key"] === true) {
                // Caller has no kit for this group — surface via hidden_groups
                // (skipped here; will be picked up by envelope scan below).
                continue;
            }
            for (const [k, v] of Object.entries(b)) {
                fields[k] = v;
            }
        }
        // Public envelope extras + group ciphertext bookkeeping for hidden_groups.
        for (const [k, v] of Object.entries(env)) {
            if (ENVELOPE_BASICS.has(k))
                continue;
            if (v !== null &&
                typeof v === "object" &&
                !Array.isArray(v) &&
                "ciphertext" in v) {
                // Group block. Surface as hidden if we couldn't decrypt it.
                const pt = plaintext[k];
                const hadKey = pt !== undefined &&
                    (typeof pt !== "object" ||
                        pt === null ||
                        !(pt["$no_read_key"] === true));
                if (!hadKey)
                    hidden.push(k);
                continue;
            }
            // Non-group public envelope extra (e.g. handler-injected).
            fields[k] = v;
        }
        // run_id and message are plaintext-payload but hoisted to typed
        // envelope slots so callers use `e.run_id` / `e.message` rather
        // than reaching into `e.fields`.
        let runId;
        if ("run_id" in fields) {
            runId = String(fields["run_id"] ?? "");
            delete fields["run_id"];
        }
        else {
            runId = String(env["run_id"] ?? "");
        }
        let message;
        if ("message" in fields) {
            const v = fields["message"];
            message = v === null || v === undefined ? null : String(v);
            delete fields["message"];
        }
        else {
            const ev = env["message"];
            message = ev === undefined || ev === null ? null : String(ev);
        }
        return new Entry({
            event_type: String(env["event_type"] ?? ""),
            timestamp: _coerceTimestamp(env["timestamp"]),
            level: String(env["level"] ?? ""),
            message,
            fields,
            did: String(env["did"] ?? ""),
            event_id: String(env["event_id"] ?? ""),
            sequence: Number(env["sequence"] ?? 0),
            run_id: runId,
            prev_hash: String(env["prev_hash"] ?? ""),
            row_hash: String(env["row_hash"] ?? ""),
            signature: String(env["signature"] ?? ""),
            hidden_groups: [...new Set(hidden)].sort(),
        });
    }
    /**
     * Build an Entry from the legacy flat-dict shape produced by
     * `flattenRawEntry`. Keys not in the envelope schema land in
     * `fields`; legacy underscore-prefixed metadata (`_decrypt_errors`,
     * `_valid`) is dropped.
     */
    static fromFlat(d) {
        const kwargs = {};
        const userFields = {};
        let hiddenGroups = [];
        for (const [k, v] of Object.entries(d)) {
            if (k === "_hidden_groups") {
                hiddenGroups = Array.isArray(v) ? v.map(String) : [];
            }
            else if (k.startsWith("_")) {
                continue;
            }
            else if (ENVELOPE_KEYS_FROM_FLAT.has(k)) {
                kwargs[k] = v;
            }
            else {
                userFields[k] = v;
            }
        }
        // Only the truly identity-bearing fields are required. Crypto
        // plumbing (`prev_hash`, `row_hash`, `signature`) is excluded from
        // `flattenRawEntry`'s output, so the watch path never carries it; we
        // default-fill below.
        for (const required of ["event_type", "did", "event_id", "sequence"]) {
            if (!(required in kwargs)) {
                throw new Error(`Entry.fromFlat: required envelope field ${JSON.stringify(required)} ` +
                    `missing from input dict (keys=${JSON.stringify(Object.keys(d).sort())})`);
            }
        }
        // run_id and message may live in either bucket — hoist either way.
        let runId;
        if ("run_id" in kwargs) {
            runId = String(kwargs["run_id"] ?? "");
            delete kwargs["run_id"];
        }
        else if ("run_id" in userFields) {
            runId = String(userFields["run_id"] ?? "");
            delete userFields["run_id"];
        }
        else {
            runId = "";
        }
        let message;
        if ("message" in kwargs) {
            const v = kwargs["message"];
            message = v === null || v === undefined ? null : String(v);
            delete kwargs["message"];
        }
        else if ("message" in userFields) {
            const v = userFields["message"];
            message = v === null || v === undefined ? null : String(v);
            delete userFields["message"];
        }
        else {
            message = null;
        }
        return new Entry({
            event_type: String(kwargs["event_type"]),
            timestamp: _coerceTimestamp(kwargs["timestamp"]),
            level: String(kwargs["level"] ?? ""),
            message,
            fields: userFields,
            did: String(kwargs["did"]),
            event_id: String(kwargs["event_id"]),
            sequence: Number(kwargs["sequence"]),
            run_id: runId,
            prev_hash: String(kwargs["prev_hash"] ?? ""),
            row_hash: String(kwargs["row_hash"] ?? ""),
            signature: String(kwargs["signature"] ?? ""),
            hidden_groups: hiddenGroups,
        });
    }
    // -----------------------------------------------------------------
    // Human-readable
    // -----------------------------------------------------------------
    /** One-line scannable view; mirrors Python `Entry.__str__`. */
    toString() {
        const ts = _formatHHMMSSmmm(this.timestamp);
        const lvl = this.level.toUpperCase().padEnd(7, " ");
        const head = `${ts} ${lvl} seq=${this.sequence}  ${this.event_type}`;
        const keys = Object.keys(this.fields);
        if (keys.length > 0) {
            const kvs = keys.map((k) => `${k}=${_pyRepr(this.fields[k])}`).join("  ");
            return `${head}  ${kvs}`;
        }
        return head;
    }
    /** Plain object suitable for `JSON.stringify`. Mirrors Python `model_dump`. */
    toJSON() {
        return {
            event_type: this.event_type,
            timestamp: this.timestamp.toISOString(),
            level: this.level,
            message: this.message,
            fields: { ...this.fields },
            did: this.did,
            event_id: this.event_id,
            sequence: this.sequence,
            run_id: this.run_id,
            prev_hash: this.prev_hash,
            row_hash: this.row_hash,
            signature: this.signature,
            hidden_groups: [...this.hidden_groups],
        };
    }
    /** Developer-facing — used by `console.log` / Node's `util.inspect`. */
    [NODE_INSPECT_CUSTOM]() {
        const didShort = this.did.length > 30 ? `${this.did.slice(0, 16)}...${this.did.slice(-8)}` : this.did;
        const fieldsDump = JSON.stringify(this.fields);
        const fieldsRepr = fieldsDump.length <= 60 ? fieldsDump : `{...${Object.keys(this.fields).length} kwargs}`;
        return (`Entry(event_type=${JSON.stringify(this.event_type)}, ` +
            `timestamp=${JSON.stringify(this.timestamp.toISOString())}, ` +
            `level=${JSON.stringify(this.level)}, ` +
            `sequence=${this.sequence}, ` +
            `did=${JSON.stringify(didShort)}, ` +
            `fields=${fieldsRepr})`);
    }
}
//# sourceMappingURL=Entry.js.map