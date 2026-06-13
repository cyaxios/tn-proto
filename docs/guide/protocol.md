# TN protocol reference

This is the on-the-wire definition of the TN protocol, derived from the
Rust core (`crypto/tn-core` and `crypto/tn-btn`), which is the engine both
the Python and TypeScript SDKs run through. Every record both SDKs write is
byte-identical because both call this core.

A TN log is append-only NDJSON: one JSON record per line. Each record is a
small public header plus one encrypted block per group, with the header
hash-chained to the record before it and (by default) signed by the writer's
device key. Reading a record back means verifying that chain and signature,
then decrypting the groups for which you hold a reader kit.

> This document describes the wire format for **readers and verifiers**. Do not
> reimplement the writer: always produce records through an SDK, which runs the
> one shared Rust core. Any byte-divergence in a hand-rolled writer breaks
> cross-language verification.

This reference has four parts:

1. **The record** - the exact JSON shape of one log line: header fields,
   per-group ciphertext blocks, and the equality-search token block.
2. **Integrity** - how the bytes are made tamper-evident: canonicalization,
   the per-event-type row-hash chain, Ed25519 signing, and the HMAC index
   tokens.
3. **BTN** - the broadcast cipher that lets one encrypted block be read by
   many recipients, plus rotation and revocation.
4. **The `tn.agents` policy group** - the one reserved group whose field set
   the protocol defines: the publisher's governance declaration, sealed and
   signed onto every record of an event type.

---

## 1. The record (on-the-wire envelope)

Every TN event is written to the log as exactly one line of newline-terminated
JSON (ndjson). That line is the **record**, also called the **envelope**. This
document describes the exact JSON shape the Rust core produces, field by field,
citing the authoritative source.

Signing is on by default (the `transaction` profile), which makes a signed
record non-repudiable. It is not universal: the `telemetry` and `stdout`
profiles do not sign, and an unsigned record carries an empty `signature` (see
[signature](#signature)). A reader must not assume every record is signed.

The record is assembled in `crypto/tn-core/src/runtime/emit.rs` (`emit_inner`
and its stages `classify_fields`, `encrypt_groups`, `build_and_write`),
serialized to a string by `crypto/tn-core/src/envelope.rs::build_envelope`, and
appended to the log by `crypto/tn-core/src/log_file.rs::LogFileWriter::append_line`.

This section covers the **record shape only**. The math behind `row_hash`, the
Ed25519 signature, the per-field equality-index tokens, and the group ciphertext
is described in [§2, the integrity layer](#2-integrity-layer-canonical-bytes-hash-chain-signing-index-tokens);
here we only document what those values look like in the record.

### Example record

The example below was produced by:

```
tn init demoproto --no-link --skip-confirm
tn info --yaml .tn/demoproto/tn.yaml --event tn.demo --field amount=42 --field note=hello
```

then reading the resulting ndjson log line and pretty-printing it. On the wire it
is a single line with no whitespace (`serde_json` with `separators=(",", ":")`
equivalent — see `envelope.rs:8`); it is expanded here only for readability:

```json
{
  "device_identity": "did:key:z6MkmXZz3niJcQjT7eF13hUX3eqTVKyWZe4CLgRdmL7Sff3e",
  "timestamp": "2026-06-08T15:35:20.246576Z",
  "event_id": "019ea7df-c3b6-7c22-b2f4-a6b870588ffa",
  "event_type": "tn.demo",
  "level": "info",
  "sequence": 1,
  "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "row_hash": "sha256:b4021deba3c52905d3d816ac56c4be36cf0be9756e63eef3413645ee053573e5",
  "signature": "evV2GGs6ZNs0cc1AFXpGb-uIym_1sjHNG2jutOB_Xvb_RdwDd2yxjwqFiuTUrJazVNO7pyzPxvv2noqF771NDA",
  "default": {
    "ciphertext": "twEBipuaixOrx+t2GT7aBsM8EnKkd5PbQDeIY0pfeFHpcN0AAAAAAAEARMKuNxZjOOACWv9SEKllfN+FDjOs97xhoWkDIrBirh/IPvhDyROAeUkJBx8UR9KtfaUNLAAAAFp29BPf9P98lj1o4Z494Y0XvoUknNZlLPt1hT7yVTHU0+cwp+aiSvoK2v+NuLPCANWMVdN6xhAfeanAcFQAgB5z0ihSJEpR+/UJMZSkhTiZDotFzEAaNthYsgE=",
    "field_hashes": {
      "amount": "hmac-sha256:v1:7a268d8d58c9ddef59255241cdeb8454c7650c5d8d191322c76eec9488977383",
      "note": "hmac-sha256:v1:ad89d4cb7fbf9d9d7e2ff334886ba8117c82dce7d9df2c1b3d7ff3cb3c34db4d",
      "run_id": "hmac-sha256:v1:3611e993a8f370bd484ad7c655f11284bed13392fe5f2983d063ca7e87dd3052"
    }
  }
}
```

In this record the three caller fields (`amount`, `note`, and the
auto-injected `run_id`) all routed to the `default` group, so none of them
appears as a top-level public field — each shows up only as an encrypted value
inside the group ciphertext and as an index token in `field_hashes`. The `default`
key at the top level is the **group payload**, not a header field.

### Record layout, in write order

`build_envelope` writes the record in a fixed order (`envelope.rs:97-152`):

1. The **nine mandatory header fields**, always present, always first, in the
   exact order below (`envelope.rs:69-79`, `103-122`).
2. Then the **public (unencrypted) fields**, in insertion order, skipping any
   whose name collides with a mandatory header key (`envelope.rs:129-135`).
3. Then one **group payload object per group**, keyed by group name, in
   group-name order (`envelope.rs:141-147`).

The mandatory key order is the constant `MANDATORY_KEYS` (`envelope.rs:69-79`):
`device_identity, timestamp, event_id, event_type, level, sequence, prev_hash,
row_hash, signature`.

### Header fields

Each value below is filled in by `build_and_write` (`emit.rs:363-467`) and the
header-prep stage of `emit_inner` (`emit.rs:537-552`), then handed to
`build_envelope` through `EnvelopeInput` (`envelope.rs:36-64`).

#### device_identity
- **Type:** string.
- **Meaning:** the publishing device's DID (`did:key:z…`).
- **Composition:** taken from `self.device.did()` at envelope-build time
  (`emit.rs:427`); also the first field hashed into `row_hash`
  (`chain.rs:55`). Documented as the publisher device identity in
  `EnvelopeInput` (`envelope.rs:37-38`).

#### timestamp
- **Type:** string (ISO-8601 UTC, microsecond precision, `Z` suffix, e.g.
  `2026-06-08T15:35:20.246576Z`).
- **Meaning:** when the event was emitted.
- **Composition:** either the caller-supplied timestamp or, by default,
  `current_timestamp()` (`emit.rs:539`), whose format string is in
  `helpers.rs:13-16`. Also hashed into `row_hash` (`chain.rs:56`).

#### event_id
- **Type:** string (UUID v7, time-sortable).
- **Meaning:** unique id for this single emit.
- **Composition:** either caller-supplied or freshly minted as
  `Uuid::now_v7()` (`emit.rs:549`). UUID v7 puts a 48-bit millisecond
  timestamp in the high bits so sorting by `event_id` yields chronological
  order (`emit.rs:541-549`). Hashed into `row_hash` (`chain.rs:57`).

#### event_type
- **Type:** string (dotted, e.g. `tn.demo`, `order.created`).
- **Meaning:** the kind of event. Drives chain selection (each event_type has
  its own `(sequence, prev_hash)` chain) and log routing.
- **Composition:** the caller-supplied event type, validated by
  `validate_event_type` (`emit.rs:504`). Events beginning with `tn.` are
  protocol events and may route to a separate protocol-event log
  (`emit.rs:605-607`). Hashed into `row_hash` (`chain.rs:58`).

#### level
- **Type:** string, lower-cased. May be the empty string `""`.
- **Meaning:** severity. One of `debug`, `info`, `warning`, `error`, or `""`
  for a severity-less attested fact (`tn.log`).
- **Composition:** `level.to_ascii_lowercase()` (`emit.rs:550`). The
  `tn.log(...)` entry point emits with `level: ""` deliberately
  (`emit.rs:106-112`). Emits below the active level threshold are dropped
  before any record is built (`emit.rs:492-497`). Hashed into `row_hash`
  (`chain.rs:59`).

#### sequence
- **Type:** unsigned integer (`u64`).
- **Meaning:** monotonic counter **per event_type**, starting at 1.
- **Composition:** returned by `self.chain.advance(event_type)`
  (`emit.rs:809`, `867`, `903`). It is **not** part of the `row_hash` preimage
  (`RowHashInput` in `chain.rs:25-42` has no sequence field). On chained
  profiles it survives restarts (re-seeded from the log); on unchained
  profiles it resets to 1 each process start (`emit.rs:885-903`). Serialized
  as a bare JSON number (`envelope.rs:114-116`).

#### prev_hash
- **Type:** string (`sha256:` + 64 hex chars), or `""`.
- **Meaning:** the `row_hash` of the previous record in this event_type's
  chain — the linkage that makes the log tamper-evident.
- **Composition:** the second element of `self.chain.advance(event_type)`
  (`emit.rs:809`). The first record of an event_type chains from the zero
  hash, `sha256:0000…0000` (`chain.rs:13-14`, `ZERO_HASH`) — visible in the
  example. On **unchained** profiles (`ceremony.chain: false`) it is the empty
  string `""` as the explicit "no linkage claim" sentinel (`emit.rs:885-903`).
  Hashed into `row_hash` (`chain.rs:60`).

#### row_hash
- **Type:** string (`sha256:` + 64 hex chars), or `""`.
- **Meaning:** the content hash of this record; the value the next record will
  carry as its `prev_hash`, and the bytes the signature signs.
- **Composition:** `compute_row_hash` over `device_identity, timestamp,
  event_id, event_type, level, prev_hash`, then the sorted public fields, then
  the sorted group ciphertexts and field-hash tokens (`chain.rs:44-103`).
  Computed at `emit.rs:383-402`. When a profile is both unchained and unsigned
  (pure-log mode) the record carries `row_hash: ""` as the documented sentinel
  (`emit.rs:396-402`).

#### signature
- **Type:** string (URL-safe base64, no padding), or `""`.
- **Meaning:** the publisher's Ed25519 signature over the `row_hash` bytes.
- **Composition:** `self.device.sign(row_hash.as_bytes())` encoded by
  `signature_b64` (`emit.rs:412-417`), which is URL-safe base64 with no padding
  (`signing.rs:121-124`). Whether a record is signed follows the per-call
  override, else `ceremony.sign` (`emit.rs:411`). When signing is off the field
  is `""` (`emit.rs:415-417`).

### Public (unencrypted) fields

After the nine header fields, any caller field classified as **public** is
written next, in insertion order, each as a normal JSON key/value
(`envelope.rs:129-135`). A field becomes public when it is listed under
top-level `public_fields` in `tn.yaml`, or routed to a group whose policy is
`public` (`emit.rs:284-345`, `classify_fields`).

Public fields are written verbatim (`build_envelope` delegates them to
`serde_json` so their keys and string values are correctly escaped —
`envelope.rs:124-135`, `169-178`). A public field whose name collides with a
mandatory header key is silently skipped — header keys always win
(`envelope.rs:69-71`, `129-132`).

Public fields are also part of the `row_hash` preimage, hashed in sorted order
as `key=<value>\x00` (`chain.rs:66-72`).

In the example record there are no public fields: `default` is not a public
group, so `amount`, `note`, and `run_id` were all encrypted. A record with, for
example, a public `region` field would carry `"region":"us-east"` as a plain
top-level key between `signature` and the first group payload.

### Group payloads (encrypted fields)

Every group that received at least one field for this emit contributes one
top-level key, named after the group (e.g. `default`), whose value is a
**group-payload object** with exactly two keys (`envelope.rs:21-29`,
`GroupPayload`):

```json
"default": {
  "ciphertext": "<standard base64>",
  "field_hashes": { "<field>": "<index token>", ... }
}
```

#### ciphertext
- **Type:** string (standard base64, with padding).
- **Meaning:** the encrypted, canonicalized bundle of all fields that routed to
  this group for this emit.
- **Composition:** the group's fields are sorted, canonicalized to bytes
  (`canonical_bytes`), and encrypted under the group cipher
  (`emit.rs:204-220`). The raw ciphertext bytes are serialized as standard
  base64 (`envelope.rs:24-26`, `31-33`). The byte structure inside the
  ciphertext (cipher header, recipient blocks, etc.) is a separate concern; at
  the record level it is one opaque base64 string.

#### field_hashes (the equality-index HMAC tokens)
- **Type:** JSON object, **field name → token string**, sorted by field name
  (`BTreeMap`, `envelope.rs:28`).
- **Meaning:** a per-field equality-index token. It lets a reader test
  `field == value` and join across records without decrypting the ciphertext,
  while revealing nothing about the plaintext beyond equality.
- **Record shape:** each value is a string of the form
  `hmac-sha256:v1:<64 hex chars>` — the literal prefix `hmac-sha256:v1:`
  (`indexing.rs:21`, `INDEX_TOKEN_PREFIX`) followed by a 64-char hex HMAC-SHA256
  digest (`indexing.rs:104-112`). One entry is produced per field routed to the
  group (`emit.rs:187-193`).
- The derivation of each token (the HMAC keying and canonicalization) is
  documented in [§2, equality-index HMAC tokens](#equality-index-hmac-tokens);
  here we record only that the block is the `field_hashes` map inside each group
  payload. There is **no** separate top-level index-tokens block in the
  record — the tokens live inside each group's payload.

Both `ciphertext` and the sorted `field_hashes` also feed `row_hash`: per group,
the preimage includes `group:<name>\x00 ct:<ciphertext-bytes>\x00` then each
`<field>=<token>\x00` in sorted order (`chain.rs:74-89`).

Note `run_id`: the runtime auto-injects a `run_id` field into every emit unless
the caller already supplied one (`emit.rs:508-510`). It is classified and routed
like any other field, which is why it appears among `field_hashes` in the
example (it routed into `default` and was encrypted, not surfaced as a public
field).

### Field-by-field reference

| field | where | type | description |
| --- | --- | --- | --- |
| `device_identity` | header (mandatory) | string | Publisher DID `did:key:z…`; `self.device.did()` (`emit.rs:427`). |
| `timestamp` | header (mandatory) | string | ISO-8601 UTC, microsecond `Z` (`helpers.rs:13-16`); caller or `current_timestamp()` (`emit.rs:539`). |
| `event_id` | header (mandatory) | string | UUID v7, time-sortable; caller or `Uuid::now_v7()` (`emit.rs:549`). |
| `event_type` | header (mandatory) | string | Dotted event kind; validated (`emit.rs:504`); selects the chain. |
| `level` | header (mandatory) | string | Lower-cased severity; `""` for severity-less `tn.log` (`emit.rs:550`, `106-112`). |
| `sequence` | header (mandatory) | integer (`u64`) | Per-event_type monotonic counter from `chain.advance` (`emit.rs:809`); not in `row_hash`. |
| `prev_hash` | header (mandatory) | string | `sha256:`+64 hex of prior row, `ZERO_HASH` at chain start, `""` when unchained (`chain.rs:13-14`, `emit.rs:885-903`). |
| `row_hash` | header (mandatory) | string | `sha256:`+64 hex content hash (`chain.rs:50-103`); `""` in pure-log mode (`emit.rs:396-402`). |
| `signature` | header (mandatory) | string | URL-safe base64 no-pad Ed25519 over `row_hash` bytes (`signing.rs:121-124`); `""` when unsigned. |
| *(public fields)* | top level, after header | any JSON | Caller fields whose route is public; insertion order; collisions with header keys skipped (`envelope.rs:129-135`). |
| `<group>` | top level, after public fields | object | One group-payload object per group that received a field; key is the group name (`envelope.rs:141-147`). |
| `<group>.ciphertext` | inside group payload | string | Standard base64 of the encrypted, canonicalized group fields (`envelope.rs:24-26`, `emit.rs:204-216`). |
| `<group>.field_hashes` | inside group payload | object | Sorted `field → hmac-sha256:v1:<64 hex>` equality-index tokens (`envelope.rs:28`, `indexing.rs:21`/`104-112`). |
| `run_id` | inside a group's `field_hashes` / `ciphertext` (or public if routed public) | string | Auto-injected per emit unless caller supplies it (`emit.rs:508-510`); classified and routed like any field. |

### Notes on framing

- One record is exactly one line of JSON terminated by a single `\n`; the
  newline is appended by `build_envelope` itself (`envelope.rs:149-151`) and the
  writer appends the line as-is (`log_file.rs:270-300`).
- The reader splits on `\n` and parses each non-empty line independently
  (`log_file.rs:491-504`), so a single malformed line is skippable without
  losing the rest of the log.
- Key order in the record is significant for cross-implementation byte-equality:
  `serde_json` runs with the `preserve_order` feature so the insertion order set
  by `build_envelope` is the on-disk order (`envelope.rs:9-11`).


---

## 2. Integrity layer (canonical bytes, hash chain, signing, index tokens)

This section describes the math behind a TN record: how a value is turned into
deterministic bytes, how those bytes feed the `row_hash`, how records link into a
per-`event_type` hash chain, how the `row_hash` is signed with Ed25519, and how
the per-field equality-index HMAC tokens are derived.
[§1, the record](#1-the-record-on-the-wire-envelope) describes the on-the-wire
envelope shape; here we cover the cryptographic construction, citing the
authoritative Rust core (`crypto/tn-core`).

The values below were produced by:

```
tn init demoproj --no-link --skip-confirm --keep-mnemonic
tn info --yaml .tn/demoproj/tn.yaml --event order.created --field amount=100 --field currency=USD
```

then reading the resulting ndjson log line. The record:

```json
{
  "device_identity": "did:key:z6MkqiT4Zjb1D67eVTToq5YTVKMhxKxN1MNESps3eK2kLyG7",
  "timestamp": "2026-06-08T15:35:54.837317Z",
  "event_id": "019ea7e0-4ad5-75c1-a1c9-ba6870b65e24",
  "event_type": "order.created",
  "level": "info",
  "sequence": 1,
  "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "row_hash": "sha256:d466060cabb16621e794dc1024135396c475cbb619b4ba27d58dfdc132142c58",
  "signature": "b9Oe-KtOq_IxBcoeS0Ue04bRxQjDE5AdSdCySnl7bOs__6-hmm10kb_2YAfYyjnTi5UYixmbUZxgTKuEMiOSAQ",
  "default": {
    "ciphertext": "twEB6447F0fBPDY6wPCWK4sLknFcg9WTl9vlM60rci437UQAAAAAAAEAjg...",
    "field_hashes": {
      "amount": "hmac-sha256:v1:30a3cfa3ce704cc7d8e1ea3943c5f8d2c5650c31f1a5a35b724c02156de392f7",
      "currency": "hmac-sha256:v1:dd404179c2144de51be831edf3d4096c7a3bec61c2918fc367bb125ebad5915d",
      "run_id": "hmac-sha256:v1:b5f1f38165a5b598d4831a473c432cb7c9d7ef0e45baa154f12433f84ca1ce70"
    }
  }
}
```

The three caller fields (`amount`, `currency`, the auto-injected `run_id`) all
routed to the `default` group, so none appears as a top-level public field; each
shows up only inside the group ciphertext and as an index token in
`field_hashes`. The values in this record drive every worked example below.

### Canonical bytes

The canonical form is a deterministic JSON serialization (an RFC 8785 subset).
It is the byte form that field-index tokens hash over, and it must match the
Python implementation byte-for-byte. The rules, from
`crypto/tn-core/src/canonical.rs`:

- **Sorted keys at every nesting level.** Object keys are collected and sorted
  before emission (`canonical.rs:53-55`); nesting recurses, so inner objects are
  sorted too.
- **Compact separators.** No whitespace anywhere: `,` between elements, `:`
  between key and value (`canonical.rs:56-60`, `canonical.rs:44`).
- **UTF-8 output, non-ASCII preserved.** BMP and astral characters are written
  as raw UTF-8, not `\uXXXX` escapes (`canonical.rs:83-86`). Only the JSON
  structural escapes and C0 control characters are escaped: `"`, `\`, `\n`,
  `\r`, `\t`, `\b`, `\f`, and any codepoint below `0x20` as `\u00xx`
  (`canonical.rs:72-82`).
- **Numbers** are emitted via `serde_json`'s own `to_string`
  (`canonical.rs:38`); **NaN and infinity are rejected** with an error
  (`canonical.rs:31-37`).
- **Literals** `null`, `true`, `false` are written verbatim
  (`canonical.rs:27-29`).
- **Bytes** are not a native JSON type; they are pre-wrapped as
  `{"$b64": "<base64>"}` by `wrap_bytes` before serialization
  (`canonical.rs:92-97`).

Real example, via the `tn canonical` verb, which echoes the canonical bytes of
each stdin JSON line:

```
$ echo '{"b":"x","a":1,"nested":{"z":true,"y":null}}' | tn canonical
{"a":1,"b":"x","nested":{"y":null,"z":true}}
```

The input keys `b, a, nested` come back sorted to `a, b, nested`, and the inner
object `{"z":true,"y":null}` comes back as `{"y":null,"z":true}`; sorting is
recursive. There is no whitespace in the output.

### Row hash

The `row_hash` is `"sha256:" + hex(sha256(...))`
(`crypto/tn-core/src/chain.rs:44`, `chain.rs:94-95`). The input fields are listed
in `RowHashInput` (`chain.rs:25-42`) and the byte layout is in `compute_row_hash`
(`chain.rs:50-103`). Each token is followed by a single `\x00` separator byte.
The composition order is exactly:

1. **Six envelope scalars**, each followed by `\x00`, in this order
   (`chain.rs:53-64`): `device_identity`, `timestamp`, `event_id`, `event_type`,
   `level`, `prev_hash`.
2. **Public fields**, sorted by key (a `BTreeMap`, so already ordered), each
   emitted as `key` + `=` + rendered-value + `\x00` (`chain.rs:66-72`). The value
   is rendered the way Python `str()` would: strings as raw UTF-8 with no quotes,
   `true`/`false` as `True`/`False`, `null` as `None`, numbers as their decimal
   string (`render_value`, `chain.rs:112-125`).
3. **Groups**, sorted by name (`chain.rs:74-89`). For each group: `group:` +
   name + `\x00`, then `ct:` + raw ciphertext bytes + `\x00`, then for each
   field (sorted) `fname` + `=` + index-token + `\x00`. The ciphertext fed here
   is the raw (decoded) bytes, not the base64 text that appears in the envelope
   (`chain.rs:19`, `chain.rs:79`).

The hash algorithm is SHA-256 (`chain.rs:8`, `chain.rs:51`).

In the example record there are no top-level public fields (all three caller
fields routed to the `default` group), so stage 2 contributes nothing and stage 3
covers the single `default` group. Reconstructing the hash from the record by
decoding the ciphertext from base64, feeding the six scalars, then `group:default`,
the raw ciphertext, and the three sorted `field_hashes`, reproduces the record's
value exactly:

```
sha256:d466060cabb16621e794dc1024135396c475cbb619b4ba27d58dfdc132142c58
```

Because the ciphertext bytes and every field's index token are folded into the
hash, the `row_hash` binds the record's encrypted payload and its searchable
tokens together: changing any byte of the ciphertext or any index token changes
the `row_hash`, which in turn invalidates the signature.

### Hash chain

The chain is **per `event_type`, not global**. Chain state is a
`HashMap<String, EventChain>` keyed by `event_type` (`chain.rs:140-142`), where
each `EventChain` holds an independent monotonic `seq` and `prev_hash`
(`chain.rs:131-135`). Every `event_type` starts at `seq=0` with
`prev_hash = ZERO_HASH` (`chain.rs:13-14`, `chain.rs:161-164`), the sentinel
`sha256:` followed by 64 zero hex chars. In the example record the first
`order.created` event carries `sequence: 1` and the zero `prev_hash`, confirming
this `event_type` chain started fresh.

On append, the runtime resolves the chain tip, then advances and commits:

- `advance(event_type)` increments that `event_type`'s sequence and returns
  `(next_seq, prev_hash)` where `prev_hash` is the previous row's hash for the
  same `event_type` (`chain.rs:157-167`). The runtime calls it at
  `runtime/emit.rs:809` / `emit.rs:867`.
- After the row is materialized, `commit(event_type, row_hash)` stores the new
  `row_hash` as that `event_type`'s `prev_hash` for the next append
  (`chain.rs:174-179`; called at `emit.rs:846` / `emit.rs:882`).

Because `ChainState` is per-process, multiple workers writing the same
`event_type` could otherwise advance from a stale in-memory view. To prevent
conflicting `prev_hash` values, the cross-process emit lock re-derives the tip
from the log file on disk before advancing. The tip-finding helpers all key on
`event_type`:

- `chain_tips_from_ndjson` forward-scans the whole log and returns the latest
  `(sequence, row_hash)` per `event_type`, last-write-wins (`chain.rs:218-242`).
- `chain_tip_from_log_tail_reverse` walks one log backward and returns the most
  recent matching row for a single `event_type`, stopping early, the hot path
  for one emit (`chain.rs:258-296`).
- `chain_tip_from_log_files_reverse` extends the reverse scan across rotated
  backups, newest first, so the first emit of an `event_type` after a log
  rotation still chains off the pre-rotation tip (`chain.rs:312-322`).

Malformed lines, and lines missing `event_type` / `sequence` / `row_hash`, are
silently skipped by all three; finding the tip is the goal, validation is the
reader's job (`chain.rs:209-217`). A reader verifies the chain by recomputing
each row's `row_hash` (see above) and checking that within an `event_type` the
`sequence` increments by one and each record's `prev_hash` equals the previous
record's `row_hash`, with the first record's `prev_hash` equal to `ZERO_HASH`.

### Signing

Records are signed with Ed25519. The signed message is the `row_hash` **string
bytes**, including the `sha256:` prefix: the runtime calls
`self.device.sign(row_hash.as_bytes())` (`runtime/emit.rs:413`). Signing is
gated by the per-call override or the ceremony `sign` default
(`emit.rs:411-417`); when unsigned, the field is empty.

The key and encoding live in `crypto/tn-core/src/signing.rs`:

- `DeviceKey` wraps an Ed25519 `SigningKey` + `VerifyingKey` and a cached
  `did:key` (`signing.rs:16-21`). It is loaded from a 32-byte seed
  (`from_private_bytes`, `signing.rs:33-53`).
- `sign` produces a 64-byte Ed25519 signature (`signing.rs:84-86`).
- The signature is encoded as **URL-safe base64 with no padding**
  (`signature_b64`, `signing.rs:121-124`; decode via `signature_from_b64`,
  `signing.rs:127-132`).
- **did:key derivation**: the public key is prefixed with the Ed25519 multicodec
  `[0xed, 0x01]` (`signing.rs:14`, `signing.rs:45-46`), base58-btc encoded, and
  formatted as `did:key:z<base58>` (`signing.rs:47`). The leading `z` is the
  multibase base58-btc indicator and is outside the base58 payload.

A reader verifies with `verify_did(did, message, signature)` (`signing.rs:91-118`):
strip the `did:key:z` prefix, base58-decode, check the first two bytes are the
Ed25519 multicodec, take the remaining 32 bytes as the public key, and verify the
64-byte signature against the message (the `row_hash` bytes). Non-Ed25519 DIDs
(for example secp256k1 ATProto identities) return `Ok(false)` rather than
erroring (`signing.rs:5-6`, `signing.rs:101-103`).

For the example record, decoding `device_identity` per the steps above yields a
32-byte Ed25519 public key, and that key verifies the 64-byte `signature` over
the ASCII bytes of `row_hash`, confirming the signature covers the chained,
content-bound hash and therefore everything the hash binds.

### Equality-index HMAC tokens

Each encrypted field carries a keyed equality token in `field_hashes` so that two
records sharing the same value for a field produce the same token, enabling
equality search over encrypted data without revealing plaintext. Two records with
different values produce unrelated tokens, and the token cannot be reversed to the
value without the per-group key. The construction is in
`crypto/tn-core/src/indexing.rs`.

**Per-group index key (HKDF-SHA256).** The per-group key is derived from the
per-ceremony 32-byte master index secret via HKDF-SHA256
(`derive_group_index_key`, `indexing.rs:26-51`). The HKDF salt is `None`; the
`info` string binds the key to the `(ceremony_id, group_name, epoch)` tuple
(`indexing.rs:38-44`):

```
info = b"tn-index:v1:" + ceremony_id + b":" + group_name + b":" + decimal(epoch)
```

The output is a 32-byte group key. Because the master secret never leaves the
keystore and the `info` string scopes the key per ceremony, group, and epoch, the
same plaintext in two different groups (or after an epoch rotation) yields
different tokens.

**Field token (HMAC-SHA256).** The token is HMAC-SHA256 under the group index
key over `field_name || 0x00 || canonical_bytes(value)`, formatted as
`"hmac-sha256:v1:" + lowercase-hex(tag)` (`indexing.rs:91-113`,
`INDEX_TOKEN_PREFIX` at `indexing.rs:21`). The `field_name` plus the `0x00`
separator is a domain separation so the same value under two different field
names produces different tokens (`indexing.rs:97-98`); the value contribution is
the canonical bytes from the section above (`indexing.rs:99`), so token equality
follows canonical-byte equality. `index_token` builds a fresh HMAC per call
(`indexing.rs:59-69`); the hot path caches a keyed HMAC template via
`build_hmac_template` (`indexing.rs:75-84`) and clones it per field in
`index_token_with_template` (`indexing.rs:91-96`) to skip re-keying.

For the example record, deriving the `default` group key from the ceremony's
`index_master.key` with `ceremony_id = "local_6fa7edd1"`, `group_name =
"default"`, `epoch = 0`, then taking HMAC-SHA256 over `amount\x00"100"` (the
`--field` value is a string, so its canonical bytes are the quoted JSON string
`"100"`) reproduces the record's token exactly:

```
amount   -> hmac-sha256:v1:30a3cfa3ce704cc7d8e1ea3943c5f8d2c5650c31f1a5a35b724c02156de392f7
currency -> hmac-sha256:v1:dd404179c2144de51be831edf3d4096c7a3bec61c2918fc367bb125ebad5915d
```

A search service holding the per-group key can compute the token for a query
value and match it against `field_hashes` to find records with that value,
without ever decrypting the ciphertext or learning the plaintext of
non-matching records. It learns only equality (which records share a value), not
the values themselves.

### NDJSON log framing

The log is newline-delimited JSON: each record is exactly one line of compact
JSON (no internal whitespace) terminated by `\n`, appended to the log file. The
tip-finding helpers split the log on `\n` and parse each non-empty line
independently (`chain.rs:220-223`, `chain.rs:266-275`), and trailing newlines are
tolerated: a final line without a `\n` still scans as one line
(`chain.rs:262-268`). This framing makes the log append-only and line-addressable:
a reader can stream it line by line, and the reverse-scan tip helpers can walk it
backward from the end. The exact per-field on-the-wire shape of one line is
documented in [§1, the record](#1-the-record-on-the-wire-envelope).


---

## 3. BTN, the broadcast cipher

BTN ("broadcast transaction" encryption) is the per-group cipher that lets one
encrypted record block be read by N recipients, each holding their own private
reader kit, without the publisher re-encrypting once per recipient. It is the
first-class cipher in `tn-core`; the `jwe` cipher remains the per-recipient
alternative.

This page describes BTN from the authoritative Rust source. The cipher lives in
the `tn-btn` crate (`crypto/tn-btn/`) and is bridged into the per-group
`GroupCipher` surface by `crypto/tn-core/src/cipher/btn.rs`.

The scheme is NNL subset-difference broadcast encryption with selective
revocation over a complete binary tree. In v0.1 the tree height is hard-coded at
8 (256 leaves); this is a configuration constant, not a wire-format limit
(`crypto/tn-btn/src/lib.rs:17-22`).

### The problem BTN solves

A TN record's encrypted fields are grouped. Every field routed to a group is
sealed once, into a single ciphertext block, and that one block must be readable
by every current member of the group. The naive approach is to encrypt the
payload separately for each recipient (a JWE-style per-recipient wrap). That
makes the record size grow linearly with the audience and forces a re-encrypt
whenever the audience changes.

BTN avoids per-recipient re-encryption. The publisher seals the group payload
under a single fresh content-encryption key (CEK), then wraps that CEK once per
*subset* in an NNL subset-difference cover of the non-revoked recipient set
(`crypto/tn-btn/src/ciphertext.rs:80-124`). The number of wraps is bounded by
the size of the cover, which is proportional to the number of revoked leaves and
is independent of the number of *entitled* recipients. A reader who holds an
entitled kit finds the one cover entry their keyset can unwrap, recovers the
CEK, and opens the body (`crypto/tn-btn/src/ciphertext.rs:136-154`). No reader
talks to the publisher to decrypt, and the publisher never enumerates the
audience at encrypt time.

Contrast with the `jwe` path. JWE is standard per-recipient crypto (X25519 +
HKDF + AES-KW + AES-GCM); each recipient gets their own wrapped key and adding a
recipient means producing another wrap. In the btn-first plan, JWE groups stay
Python-owned: the Rust `JwePlaceholder` returns `Error::NotImplemented` for both
encrypt and decrypt, pointing the operator to run the ceremony from Python or
migrate the group to btn (`crypto/tn-core/src/cipher/jwe.rs:11-28`). The
structural difference is that BTN's per-record cost scales with revocations, not
with audience size, and a single sealed block serves the whole group.

### PublisherState

`PublisherState` is the publisher's secret state for one BTN group. It owns the
master seed and all derived key material
(`crypto/tn-btn/src/publisher.rs:52-70`):

- `publisher_id` — a 256-bit identifier derived deterministically from the
  master seed via HKDF (`crypto/tn-btn/src/publisher.rs:555-562`). Stable across
  restarts; copied into every ciphertext so readers can reject foreign content
  up-front.
- `epoch` — starts at 0, bumps on each rotation
  (`crypto/tn-btn/src/publisher.rs:118-126`).
- `master_seed` — a 32-byte secret, held in `Zeroizing` so it is wiped on drop.
  Loss means the publisher can no longer encrypt; leak is catastrophic (the
  holder can mint arbitrary kits and decrypt everything this publisher ever
  produced, `crypto/tn-btn/src/publisher.rs:45-51`).
- `node_key_cache` — every internal node's primary key, eagerly populated at
  setup so repeated encrypts reuse the tree walk
  (`crypto/tn-btn/src/publisher.rs:564-589`). Not serialized; rebuilt from the
  seed on load.
- `issued` / `revoked` — `BTreeSet<LeafIndex>` bookkeeping; disjoint by
  construction (revoking moves a leaf from `issued` to `revoked`).
- `next_leaf` — monotonic leaf cursor; revoked leaves are never reused
  (`crypto/tn-btn/src/publisher.rs:9-19`).

Setup from a seed. `PublisherState::setup(config)` draws a random 32-byte seed
from the OS RNG; `PublisherState::setup_with_seed(config, seed)` takes a caller-
supplied seed for deterministic ceremonies and tests. Both funnel into
`with_seed_inner`, which derives the `publisher_id`, populates the node-key
cache, and initializes empty issued/revoked sets at epoch 0
(`crypto/tn-btn/src/publisher.rs:78-108`). Setup is deterministic in the seed:
the same seed yields the same `publisher_id` and the same key tree.

On disk. The serialized state is the `<group>.btn.state` file in the keystore
(`crypto/tn-core/src/cipher/btn.rs:14-18`). `to_bytes` writes the wire header,
the master seed, epoch, `next_leaf`, and the issued/revoked leaf lists; the
node-key cache is deliberately *not* serialized and is rebuilt from the seed on
`from_bytes` (`crypto/tn-btn/src/publisher.rs:344-516`). The bytes must be
treated as secret. In `tn-core`, `BtnPublisherCipher::state_to_bytes` is the
accessor used to persist this blob
(`crypto/tn-core/src/cipher/btn.rs:101-106`).

### Reader kits (mykit)

A reader kit is the decryption material the publisher hands a single recipient.
A `ReaderKit` bundles three things (`crypto/tn-btn/src/reader.rs:21-31`):

- `publisher_id` — the publisher this kit is bound to, so the reader rejects
  ciphertexts from a different publisher before doing any crypto.
- `epoch` — the epoch this kit is bound to; a kit minted at epoch N decrypts
  epoch-N ciphertexts only.
- a `ReaderKeyset` — the actual NNL path keys plus the full-tree key for the
  reader's leaf.

Minting. `PublisherState::mint` hands out the next unused leaf, records it in the
`issued` set, materializes the reader keyset for that leaf from the master seed,
and returns a `ReaderKit` stamped with the current `publisher_id` and `epoch`
(`crypto/tn-btn/src/publisher.rs:214-226`). Leaves are assigned sequentially
from 0 and never reused; once the tree is exhausted, mint returns
`Error::TreeExhausted`. Readers cannot mint their own kits; minting is
publisher-only (`crypto/tn-btn/src/reader.rs:36-43`).

On disk. The publisher mints a kit for itself at group creation so the same
party can both write and read (the publisher-as-reader pattern). That self-kit is
stored as `<group>.btn.mykit` in the keystore
(`crypto/tn-core/src/cipher/btn.rs:14-21`). In `tn-core`,
`BtnPublisherCipher::with_reader_kit` (or `with_reader_kits`) attaches one or
more kit blobs so the publisher cipher's `decrypt` works
(`crypto/tn-core/src/cipher/btn.rs:54-78`).

How a recipient decrypts. `ReaderKit::decrypt(ct)` first checks the ciphertext's
`publisher_id` and `epoch` against the kit; a mismatch returns `NotEntitled`
with no cryptographic work. Otherwise it delegates to `decrypt_with_keyset`,
which walks the cover, finds the one entry whose subset the reader's keyset can
derive, unwraps the CEK, and AEAD-opens the body
(`crypto/tn-btn/src/reader.rs:87-92`, `crypto/tn-btn/src/ciphertext.rs:136-154`).
The reader-side `BtnReaderCipher` holds one or more kits and tries each in order;
the first successful decrypt wins, and if none cover the ciphertext it surfaces
`NotEntitled` so the read path can mark the group hidden rather than crash
(`crypto/tn-core/src/cipher/btn.rs:142-232`).

### The per-record encryption path

BTN is invoked once per group per record. The `tn-core` emit path drives it
(`crypto/tn-core/src/runtime/emit.rs:145-264`):

1. Fields are classified into a public bucket and per-group buckets
   (`classify_fields`, `crypto/tn-core/src/runtime/emit.rs:269-354`).
2. For each group, the field set is sorted and, for every field, an equality-
   index token is computed under the group's HMAC template
   (`index_token_with_template`). These tokens are the `field_hashes`:
   a sorted map of field name to HMAC token
   (`crypto/tn-core/src/runtime/emit.rs:187-199`). They let a reader or index
   match on a field value without decrypting the body. They are *not* the
   ciphertext; they are keyed hashes alongside it.
3. The sorted field object is canonicalized to bytes (`canonical_bytes`) and
   handed to the group cipher's `encrypt`
   (`crypto/tn-core/src/runtime/emit.rs:204-220`). For a BTN group this calls
   `BtnPublisherCipher::encrypt`, which runs `PublisherState::encrypt` and
   returns the wire-format ciphertext bytes
   (`crypto/tn-core/src/cipher/btn.rs:108-126`).

Inside `PublisherState::encrypt` (`crypto/tn-btn/src/publisher.rs:272-308`):

- The current `revoked` set is turned into a subset-difference cover of the tree.
- A fresh random 32-byte CEK is generated.
- For each subset label in the cover, the publisher derives that subset's key
  (cache-aware via `subset_key_cached`) and AES-KW-wraps the CEK under it,
  producing one `CoverEntry { label, wrapped_cek }`.
- The plaintext is AES-GCM-sealed under the CEK with a random nonce.
- The result is a `Ciphertext { publisher_id, epoch, cover, body_nonce, body }`.

The cipher's raw output bytes become the `ciphertext` field of the per-group
payload, and the index tokens become `field_hashes`. The two are assembled into
a `GroupPayload`, serialized as `{"ciphertext": "<base64>", "field_hashes":
{...}}`, and spliced into the envelope per group
(`crypto/tn-core/src/runtime/emit.rs:243-251`,
`crypto/tn-core/src/envelope.rs:21-33`). The `ciphertext` is standard base64;
`field_hashes` is a sorted name-to-token map.

To recover plaintext, a reader runs the inverse: confirm `publisher_id`/`epoch`,
find the cover entry their keyset can unwrap, AES-KW-unwrap the CEK, AES-GCM-open
the body, then parse the canonical JSON back into fields. If no cover entry
unwraps (revoked before this record was sealed, or a foreign publisher's keys),
the result is `NotEntitled` (`crypto/tn-btn/src/ciphertext.rs:126-154`). The
body is authenticated: a tampered body or a tampered wrapped CEK fails the AEAD
and surfaces as `NotEntitled` rather than returning corrupt plaintext
(`crypto/tn-btn/src/ciphertext.rs:240-264`).

### Rotation and revocation

Two distinct operations change who can read.

Revocation (forward only). `PublisherState::revoke(kit)` (or `revoke_by_leaf`)
moves a leaf from `issued` to `revoked`
(`crypto/tn-btn/src/publisher.rs:235-265`). It is idempotent and rejects a kit
from a different publisher. Revocation takes effect on the *next* encrypt: future
ciphertexts seal over `leaves \ revoked`, so the subset-difference cover excludes
the revoked leaf and that reader can no longer unwrap any cover entry. Records
already sealed before the revocation remain decryptable by that reader by
construction — revocation does not reach back and rewrite history. The leaf is
never reused, which avoids silently restoring a revoked reader's access if the
leaf were later re-minted (`crypto/tn-btn/src/publisher.rs:9-19`).

Rotation (epochs). `PublisherState::rotate(self)` consumes the current state and
returns a `RotationOutcome { active, retired }`
(`crypto/tn-btn/src/publisher.rs:147-192`, `crypto/tn-btn/src/rotate.rs:131-138`):

- `active` is a brand-new `PublisherState` with a fresh random master seed, a new
  `publisher_id`, a freshly built key tree, `epoch` incremented by one, and empty
  issued/revoked sets with the leaf cursor reset to 0.
- `retired` is a `RetiredPublisherState` — a frozen snapshot carrying just the
  prior `master_seed`, `publisher_id`, `epoch`, and a `retired_at_unix_secs`
  timestamp (`crypto/tn-btn/src/rotate.rs:12-21`). It omits the node-key cache,
  which is rebuilt on demand from the seed when decrypting historical
  ciphertexts.

Because each ciphertext carries its `epoch`, and a kit is bound to exactly one
epoch, a kit minted under epoch N decrypts epoch-N records only. The
`index_epoch` / epoch field is therefore the routing signal that tells a reader
which kit generation a record belongs to
(`crypto/tn-btn/src/ciphertext.rs:44-52`).

How prior-epoch records stay readable today (keywalk via retained kits). After a
rotation, the post-rotation self-kit lives at `<group>.btn.mykit`, and the
publisher's pre-rotation kits are preserved as sibling files in the keystore. At
runtime, `tn-core` collects the current kit plus every archived kit and loads
them all into a single multi-kit `BtnReaderCipher`; on each decrypt it walks the
kits in turn (newest first) until one matches the record's epoch, so pre- and
post-rotation records both read transparently
(`crypto/tn-core/src/cipher/btn.rs:30-39`,
`crypto/tn-core/src/runtime/cipher_build.rs:108-166`). The canonical archive
name for a rotation-preserved kit is `<group>.btn.mykit.retired.<epoch>`
(epoch-indexed). Each family is sorted by
its index descending so newer kits are tried first.

Open gap: retired-PublisherState archival writer (cyaxios/tn-proto#118).
`RetiredPublisherState` has a complete wire format (kind `0x04`) and round-trips
through `to_bytes` / `from_bytes` (`crypto/tn-btn/src/rotate.rs:42-128`), and the
`rotate` call produces a retired snapshot. But the on-disk archival writer that
would persist that snapshot as a `<group>.btn.state.retired.<N>` file is not
built: the read-half (`discover_retired_btn_states`) was removed as the read side
of an unwired feature, with the intent captured in cyaxios/tn-proto#118 for a
deliberate rebuild (`crypto/tn-core/src/runtime/cipher_build.rs:168-171`).
Rotation works in practice today through the retained *reader kits* described
above, not through archived retired publisher states. The retired-state archival
path is the follow-up tracked by #118.

### Wire kinds

The BTN wire format is small, versioned, and length-prefixed. Every top-level
artifact begins with a 3-byte header: magic `0xB7`, version `0x01`, then a kind
byte. All multi-byte integers are big-endian
(`crypto/tn-btn/src/wire.rs:1-64`).

| Kind byte | Constant | Meaning |
|-----------|----------|---------|
| `0x01` | `KIND_CIPHERTEXT` | A sealed broadcast `Ciphertext` (cover entries + AEAD body). |
| `0x02` | `KIND_READER_KIT` | A `ReaderKit` (publisher binding, epoch, leaf, path keys, full-tree key). |
| `0x03` | `KIND_PUBLISHER_STATE` | Serialized `PublisherState` (master seed + leaf bookkeeping); the `<group>.btn.state` file. |
| `0x04` | `KIND_RETIRED_PUBLISHER_STATE` | Serialized `RetiredPublisherState` snapshot; wire format defined, on-disk archival writer unbuilt (see cyaxios/tn-proto#118). |

Two related single-byte tags encode the subset label inside a ciphertext's cover
entries: `0x00 = SUBSET_FULLTREE`, `0x01 = SUBSET_DIFFERENCE`
(`crypto/tn-btn/src/wire.rs:56-59`). These are not top-level artifact kinds; they
appear only within a `Ciphertext` body.


---

## 4. The `tn.agents` policy group

`tn.agents` is a reserved group whose field set the protocol defines. It
carries the publisher's governance declaration for an event type - what the
data is, what it is for, what it must not be used for, what it is authoritative
for, and what to do on violation or error - sealed and signed onto every record
of that type, so a reader gets the rules from the same record as the data.

Two properties shape it. First, it **declares; it does not enforce.** The core
only splices the fields onto the record and seals them; acting on the
declaration is the job of a consuming policy engine. Second, a record carries
**exactly one** `tn.agents` block - the governance of the data is the governance
of the data, addressed to every entitled reader alike. Reader-specific content
is an ordinary group, not a second policy.

### The reserved name

`tn.agents` is the only name allowed in the `tn.*` group namespace; any other
`tn.*` group name is rejected at config load
(`crypto/tn-core/src/config.rs:567`, `Error::ReservedGroupName`). The namespace
is protocol-owned so a reader can trust the meaning of the block without
consulting the operator's config. It is otherwise an ordinary encryption group:
it has a cipher, a recipient set, and a key, and is sealed exactly like
`default` (§1, §3). A reader who does not hold the `tn.agents` key cannot read
the rules - itself a signal to a consumer that rules exist but are sealed to
another audience.

### The fields

A `tn.agents` block carries six canonically-named fields: five authored
(free-text prose, written by the publisher) and one computed. The five authored
names and their order are a protocol constant, identical across the Rust core
and both SDKs (`crypto/tn-core/src/agents_policy.rs:24`, `REQUIRED_FIELDS`):

| Field | Kind | Meaning |
|---|---|---|
| `instruction` | authored | What this record is; how to regard it (a fact to attest, not an action to re-run). |
| `use_for` | authored | The permitted uses of the data. |
| `do_not_use_for` | authored | The prohibited uses. |
| `consequences` | authored | What the record is authoritative for downstream, and the cost of getting it wrong. |
| `on_violation_or_error` | authored | What a consuming agent should do on violation or error (see below). |
| `policy` | computed | A content-addressed reference to the exact policy in force; the runtime fills it in, never the author. |

The values are free-text strings: human- and LLM-readable, carrying canonical
*meaning* but no machine-checkable structure. There is no executable callback
field. `on_violation_or_error` is the actionable directive, and it is
deliberately prose: **capability lives with the agent, not the message.** The
publisher names an action in words - "alert compliance by calling an alert
tool", "revoke the grant", "stop and surface to a human" - and a tool-equipped
consumer maps it to a tool it already holds. The record carries intent; the
tools stay with the agent. Reliability comes from the directive being sealed and
signed, not from a schema.

### The `policy` reference and content hash

The computed `policy` field is built at emit time as
(`crypto/tn-core/src/runtime/init.rs:686`):

```
<path>#<event_type>@<version>#<content_hash>
```

for example `.tn/config/agents.md#payment.completed@1#sha256:79e0aefe...`. The
`content_hash` is `sha256:` plus lowercase hex over the canonical JSON of
`{version, schema, events}`, where `events` maps each event type to its five
authored fields. Every template in one file shares this hash - it is the file's
signature. A reader pins the exact rules in force by it; a record whose `policy`
hash does not resolve to the policy the reader knows is treated as advisory.

### The splice

On every emit the runtime looks up the policy template for the record's
`event_type` and, if one exists, inserts the fields into the record's
`tn.agents` group (`crypto/tn-core/src/runtime/emit.rs:1000` calls
`splice_agent_policy`, `crypto/tn-core/src/runtime/init.rs:664`). Two rules: the
splice happens only when a matching `## <event_type>` section exists (no
section, no splice, empty block), and it uses set-default semantics - a value
passed explicitly on the emit call wins, and the template fills only what the
caller left unset. The spliced fields are then sealed into the group with the
rest of the record.

### On the wire

`tn.agents` appears as a top-level group-payload key, a sibling of the header
fields and every other group, in group-name order (§1). It has the standard
group shape:

```json
"tn.agents": {
  "ciphertext": "twEB...",
  "field_hashes": {
    "instruction":           "hmac-sha256:v1:...",
    "use_for":               "hmac-sha256:v1:...",
    "do_not_use_for":        "hmac-sha256:v1:...",
    "consequences":          "hmac-sha256:v1:...",
    "on_violation_or_error": "hmac-sha256:v1:...",
    "policy":                "hmac-sha256:v1:..."
  }
}
```

The six field values are canonicalized and sealed under the group cipher
(readable only by a holder of the `tn.agents` key), and each is indexed as an
equality-search token in `field_hashes` exactly like any group (§2). Because the
block is sealed, the rules are confidential and audience-scoped; because
`row_hash` commits the group payloads and is signed (§2), the rules cannot be
altered or stripped without invalidating the signature.

### The source file

The authored policy lives in one markdown file, `.tn/config/agents.md`, parsed
at init (`crypto/tn-core/src/agents_policy.rs:279`, `parse_policy_text`):

```markdown
---
version: 1
schema: tn-agents-policy@v1
---

## payment.completed

### instruction
This row records a captured payment. Treat it as a fact-record; never re-run
the charge it describes.

### use_for
Reconciliation, revenue reporting, a customer's payment history.

### do_not_use_for
Marketing or outreach; fraud scoring; profiling.

### consequences
Downstream systems treat this row as authoritative for "this payment was
captured."

### on_violation_or_error
If two rows disagree on amount for one payment_id, alert compliance by calling
an alert tool, then stop and surface to a human.
```

Frontmatter carries `version` (default `1`) and `schema` (default
`tn-agents-policy@v1`). Each `## <event_type>` section must contain all five
`### <field>` subsections; a missing one raises at init
(`crypto/tn-core/src/agents_policy.rs:300-315`, `Error::Malformed`), so a
published policy is never half-written.

### The `tn.agents.policy_published` event

When a runtime initializes and the policy's `content_hash` differs from the most
recently published one (or none exists), it emits a signed, synced admin event
recording the new policy (`crypto/tn-core/src/runtime/init.rs:566`; hash-change
detection at `init.rs:702`). The emitted payload:

| Field | Type | |
|---|---|---|
| `policy_uri` | string | the `.tn/config/agents.md` path |
| `version` | string | policy version |
| `content_hash` | string | `sha256:...` |
| `event_types_covered` | array of string | the governed event types |
| `policy_text` | string | the raw markdown body, for auditor replay |

The catalog (`crypto/tn-core/src/admin_catalog.rs:213`) validates the four
scalar fields; `event_types_covered` is emitted but intentionally not listed,
because the catalog does not type-check array-shaped fields. The published
history of this event is the version history of the policy: every change to the
rules is itself an attested, sealed record on the chain.

