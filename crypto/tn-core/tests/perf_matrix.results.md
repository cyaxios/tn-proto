# Performance Matrix — h=8, message size × revocation count

Captured on Windows x86_64, release build, single-threaded. Regenerate with:

```bash
cargo test --release -p tn-core --test perf_matrix -- --ignored --nocapture --test-threads=1
```

Four matrices — raw cipher, full log (emit), decrypt-only read, and
**full verified ingest** — measured on identical inputs so stages can be
compared directly.

## What each matrix covers

| Matrix | Covers | Does NOT cover |
|---|---|---|
| **btn raw cipher** | btn NNL cover + AES-256-GCM on plaintext | Anything above the cipher |
| **Runtime::emit (log)** | classify · canonical JSON of fields · HMAC-SHA256 per field · **btn encrypt** · chain mutex advance · SHA-256 row_hash over envelope · Ed25519 sign · envelope JSON serialize with preserve_order · ndjson file append · chain commit | Network / handler fanout |
| **Runtime::read (decrypt-only)** | ndjson line parse · per-group base64 decode · btn decrypt · JSON parse of plaintext · result struct build | Signature / row_hash / chain verification |
| **Full verified ingest** | Everything in read **plus** recompute row_hash from envelope fields, Ed25519 verify the signature against publisher DID, verify chain linkage (prev_hash matches previous row_hash) | Network, handler fanout |

## Quick comparison — 0 revocations baseline

p50 microseconds per event, 240 readers minted, 0 revoked:

| msg_size | raw enc | log (emit) | read (no verify) | **full ingest** | **events/s ingest** |
|---------:|--------:|-----------:|-----------------:|----------------:|--------------------:|
|     64 B |   1 µs  |    37 µs   |      8 µs        |   **58 µs**     |       **17,241**    |
|    256 B |   1 µs  |    36 µs   |      7 µs        |   **61 µs**     |       **16,393**    |
|   1024 B |   1 µs  |    51 µs   |     10 µs        |   **51 µs**     |       **19,607**    |
|   4096 B |   3 µs  |   105 µs   |     19 µs        |  **118 µs**     |        **8,474**    |
|  16384 B |  11 µs  |   218 µs   |     66 µs        |  **161 µs**     |        **6,211**    |
|  65536 B |  67 µs  | 1,079 µs   |    323 µs        |  **410 µs**     |        **2,439**    |

**events/s ingest** is the number you asked about — how many full verified
logs per second a subscriber can consume.

## Quick comparison — 225 revocations stress test

p50 microseconds per event, 240 readers minted, 225 revoked (near h=8 cap):

| msg_size | raw enc | log (emit) | read (no verify) | **full ingest** | **events/s ingest** |
|---------:|--------:|-----------:|-----------------:|----------------:|--------------------:|
|     64 B |  49 µs  |    94 µs   |     10 µs        |   **57 µs**     |       **17,543**    |
|    256 B |  63 µs  |    98 µs   |     13 µs        |   **48 µs**     |       **20,833**    |
|   1024 B |  49 µs  |   105 µs   |     10 µs        |   **65 µs**     |       **15,384**    |
|   4096 B |  50 µs  |   124 µs   |     31 µs        |   **86 µs**     |       **11,627**    |
|  16384 B |  65 µs  |   390 µs   |     62 µs        |  **139 µs**     |        **7,194**    |
|  65536 B | 106 µs  | 1,051 µs   |    218 µs        |  **313 µs**     |        **3,194**    |

Notice: **ingest is nearly insensitive to revocation count**. All the
revocation cost lives on the publisher side (cover computation during
encrypt). A subscriber's ingest rate at 225 revocations matches 0 revocations
within noise.

## Key takeaways

- **Read is consistently 3-10× faster than log** at the same (size, revocations).
  Log carries Ed25519 sign (~10-30 µs flat), canonical JSON of fields, HMAC tokens,
  row-hash over the whole envelope, and a file append + flush. Read decrypts a
  known-good blob and parses.
- **Revocation hurts log, barely touches read.** Going from 0 → 225 revocations
  at 64 B: log goes 37 µs → 94 µs (2.5× slowdown), read goes 8 µs → 10 µs
  (basically noise). The cover algorithm is only invoked on encrypt.
- **Large payloads converge** — by 64 KB both log and read are AEAD-bound.
- **Wire overhead collapses** with payload size: 178% at 64 B / 0 rev, 0.2% at 64 KB.

## Matrix 1 — btn raw cipher (publisher.encrypt)

h=8, 240 readers minted, 200 iters/cell.

| msg_size |  revoked | ct_len | enc_p50 µs | enc_p95 µs | events/s (p50) | overhead_pct |
|---------:|---------:|-------:|-----------:|-----------:|---------------:|-------------:|
|       64 |        0 |    178 |          1 |          1 |        1000000 |       178.1% |
|       64 |        1 |    609 |         22 |         26 |          45454 |       851.6% |
|       64 |        5 |    550 |         18 |         19 |          55555 |       759.4% |
|       64 |       25 |    491 |         18 |         22 |          55555 |       667.2% |
|       64 |       75 |    432 |         22 |         34 |          45454 |       575.0% |
|       64 |      150 |    373 |         30 |         42 |          33333 |       482.8% |
|       64 |      225 |    432 |         49 |         90 |          20408 |       575.0% |
|      256 |        0 |    370 |          1 |          1 |        1000000 |        44.5% |
|      256 |        1 |    801 |         19 |         22 |          52631 |       212.9% |
|      256 |        5 |    742 |         17 |         21 |          58823 |       189.8% |
|      256 |       25 |    683 |         17 |         18 |          58823 |       166.8% |
|      256 |       75 |    624 |         22 |         29 |          45454 |       143.8% |
|      256 |      150 |    565 |         31 |         48 |          32258 |       120.7% |
|      256 |      225 |    624 |         63 |         84 |          15873 |       143.8% |
|     1024 |        0 |   1138 |          1 |          2 |        1000000 |        11.1% |
|     1024 |        1 |   1569 |         20 |         24 |          50000 |        53.2% |
|     1024 |        5 |   1510 |         18 |         19 |          55555 |        47.5% |
|     1024 |       25 |   1451 |         18 |         20 |          55555 |        41.7% |
|     1024 |       75 |   1392 |         23 |         26 |          43478 |        35.9% |
|     1024 |      150 |   1333 |         31 |         51 |          32258 |        30.2% |
|     1024 |      225 |   1392 |         49 |         83 |          20408 |        35.9% |
|     4096 |        0 |   4210 |          3 |          4 |         333333 |         2.8% |
|     4096 |        1 |   4641 |         22 |         23 |          45454 |        13.3% |
|     4096 |        5 |   4582 |         20 |         21 |          50000 |        11.9% |
|     4096 |       25 |   4523 |         20 |         24 |          50000 |        10.4% |
|     4096 |       75 |   4464 |         25 |         46 |          40000 |         9.0% |
|     4096 |      150 |   4405 |         49 |         58 |          20408 |         7.5% |
|     4096 |      225 |   4464 |         50 |         81 |          20000 |         9.0% |
|    16384 |        0 |  16498 |         11 |         12 |          90909 |         0.7% |
|    16384 |        1 |  16929 |         30 |         43 |          33333 |         3.3% |
|    16384 |        5 |  16870 |         42 |         51 |          23809 |         3.0% |
|    16384 |       25 |  16811 |         35 |         43 |          28571 |         2.6% |
|    16384 |       75 |  16752 |         33 |         46 |          30303 |         2.2% |
|    16384 |      150 |  16693 |         49 |         73 |          20408 |         1.9% |
|    16384 |      225 |  16752 |         65 |         94 |          15384 |         2.2% |
|    65536 |        0 |  65650 |         67 |        101 |          14925 |         0.2% |
|    65536 |        1 |  66081 |         80 |        101 |          12500 |         0.8% |
|    65536 |        5 |  66022 |         78 |        103 |          12820 |         0.7% |
|    65536 |       25 |  65963 |         89 |        132 |          11235 |         0.7% |
|    65536 |       75 |  65904 |         82 |        125 |          12195 |         0.6% |
|    65536 |      150 |  65845 |         97 |        144 |          10309 |         0.5% |
|    65536 |      225 |  65904 |        106 |        191 |           9433 |         0.6% |

## Matrix 2 — tn-core Runtime::emit (log, full pipeline)

Classify → HMAC tokens → btn encrypt → chain advance → SHA-256 row_hash →
Ed25519 sign → envelope JSON → ndjson append. 200 iters/cell.

| msg_size | revoked | emit_p50 µs | emit_p95 µs | events/s (p50) |
|---------:|--------:|------------:|------------:|---------------:|
|       64 |       0 |          37 |          63 |          27027 |
|       64 |       1 |          57 |          86 |          17543 |
|       64 |       5 |          54 |          86 |          18518 |
|       64 |      25 |          55 |          90 |          18181 |
|       64 |      75 |          68 |          99 |          14705 |
|       64 |     150 |         105 |         155 |           9523 |
|       64 |     225 |          94 |         138 |          10638 |
|      256 |       0 |          36 |          56 |          27777 |
|      256 |       1 |          77 |         117 |          12987 |
|      256 |       5 |          71 |         103 |          14084 |
|      256 |      25 |          55 |          89 |          18181 |
|      256 |      75 |          69 |         118 |          14492 |
|      256 |     150 |          89 |         127 |          11235 |
|      256 |     225 |          98 |         165 |          10204 |
|     1024 |       0 |          51 |          91 |          19607 |
|     1024 |       1 |          63 |          98 |          15873 |
|     1024 |       5 |          65 |         118 |          15384 |
|     1024 |      25 |          86 |         129 |          11627 |
|     1024 |      75 |          71 |         127 |          14084 |
|     1024 |     150 |          72 |         118 |          13888 |
|     1024 |     225 |         105 |         170 |           9523 |
|     4096 |       0 |         105 |         160 |           9523 |
|     4096 |       1 |          94 |         144 |          10638 |
|     4096 |       5 |          93 |         170 |          10752 |
|     4096 |      25 |          91 |         154 |          10989 |
|     4096 |      75 |          93 |         160 |          10752 |
|     4096 |     150 |         103 |         149 |           9708 |
|     4096 |     225 |         124 |         226 |           8064 |
|    16384 |       0 |         218 |         392 |           4587 |
|    16384 |       1 |         252 |         386 |           3968 |
|    16384 |       5 |         229 |         358 |           4366 |
|    16384 |      25 |         280 |         402 |           3571 |
|    16384 |      75 |         323 |         440 |           3095 |
|    16384 |     150 |         437 |         602 |           2288 |
|    16384 |     225 |         390 |         510 |           2564 |
|    65536 |       0 |        1079 |        1449 |            926 |
|    65536 |       1 |        1003 |        1435 |            997 |
|    65536 |       5 |         988 |        1348 |           1012 |
|    65536 |      25 |         874 |        1336 |           1144 |
|    65536 |      75 |         831 |        1360 |           1203 |
|    65536 |     150 |         763 |        1417 |           1310 |
|    65536 |     225 |        1051 |        1391 |            951 |

## Matrix 3 — tn-core Runtime::read (full pipeline)

Per-event = `rt.read()` over a 50-event log divided by 50. 10 reads/cell.

| msg_size | revoked | read_p50 µs/event | read_p95 µs/event | events/s (p50) |
|---------:|--------:|------------------:|------------------:|---------------:|
|       64 |       0 |                 8 |                10 |         125000 |
|       64 |       1 |                 8 |                10 |         125000 |
|       64 |       5 |                 7 |                 9 |         142857 |
|       64 |      25 |                 9 |                13 |         111111 |
|       64 |      75 |                 8 |                 9 |         125000 |
|       64 |     150 |                 9 |                10 |         111111 |
|       64 |     225 |                10 |                24 |         100000 |
|      256 |       0 |                 7 |                 8 |         142857 |
|      256 |       1 |                11 |                16 |          90909 |
|      256 |       5 |                10 |                11 |         100000 |
|      256 |      25 |                 8 |                10 |         125000 |
|      256 |      75 |                 7 |                10 |         142857 |
|      256 |     150 |                 7 |                10 |         142857 |
|      256 |     225 |                13 |                19 |          76923 |
|     1024 |       0 |                10 |                18 |         100000 |
|     1024 |       1 |                11 |                13 |          90909 |
|     1024 |       5 |                17 |                20 |          58823 |
|     1024 |      25 |                10 |                11 |         100000 |
|     1024 |      75 |                12 |                24 |          83333 |
|     1024 |     150 |                11 |                20 |          90909 |
|     1024 |     225 |                10 |                12 |         100000 |
|     4096 |       0 |                19 |                40 |          52631 |
|     4096 |       1 |                29 |                35 |          34482 |
|     4096 |       5 |                21 |                30 |          47619 |
|     4096 |      25 |                26 |                44 |          38461 |
|     4096 |      75 |                32 |                36 |          31250 |
|     4096 |     150 |                28 |                30 |          35714 |
|     4096 |     225 |                31 |                35 |          32258 |
|    16384 |       0 |                66 |                95 |          15151 |
|    16384 |       1 |                77 |                89 |          12987 |
|    16384 |       5 |                82 |               123 |          12195 |
|    16384 |      25 |                68 |               119 |          14705 |
|    16384 |      75 |                62 |                70 |          16129 |
|    16384 |     150 |                66 |                80 |          15151 |
|    16384 |     225 |                62 |                75 |          16129 |
|    65536 |       0 |               323 |               349 |           3095 |
|    65536 |       1 |               226 |               253 |           4424 |
|    65536 |       5 |               230 |               301 |           4347 |
|    65536 |      25 |               238 |               284 |           4201 |
|    65536 |      75 |               186 |               259 |           5376 |
|    65536 |     150 |               207 |               245 |           4830 |
|    65536 |     225 |               218 |               253 |           4587 |

## Matrix 4 — tn-core full verified ingest

Per-event = total time for 50-event log ingestion divided by 50. 10 ingests/cell.
Each event path: parse ndjson line → recompute row_hash → verify Ed25519 signature
→ verify chain linkage → base64 decode + btn decrypt + JSON parse plaintext.

| msg_size | revoked | ingest_p50 µs/event | ingest_p95 µs/event | events/s (p50) |
|---------:|--------:|--------------------:|--------------------:|---------------:|
|       64 |       0 |                  58 |                  84 |          17241 |
|       64 |       1 |                  57 |                  90 |          17543 |
|       64 |       5 |                  59 |                  69 |          16949 |
|       64 |      25 |                  53 |                  72 |          18867 |
|       64 |      75 |                  56 |                  67 |          17857 |
|       64 |     150 |                  59 |                  63 |          16949 |
|       64 |     225 |                  57 |                 155 |          17543 |
|      256 |       0 |                  61 |                 240 |          16393 |
|      256 |       1 |                  74 |                 160 |          13513 |
|      256 |       5 |                  75 |                  81 |          13333 |
|      256 |      25 |                  49 |                  58 |          20408 |
|      256 |      75 |                  47 |                  59 |          21276 |
|      256 |     150 |                  45 |                  54 |          22222 |
|      256 |     225 |                  48 |                  65 |          20833 |
|     1024 |       0 |                  51 |                  73 |          19607 |
|     1024 |       1 |                  72 |                 106 |          13888 |
|     1024 |       5 |                  70 |                  72 |          14285 |
|     1024 |      25 |                  54 |                  87 |          18518 |
|     1024 |      75 |                  59 |                  89 |          16949 |
|     1024 |     150 |                  81 |                  88 |          12345 |
|     1024 |     225 |                  65 |                  83 |          15384 |
|     4096 |       0 |                 118 |                 286 |           8474 |
|     4096 |       1 |                  86 |                 337 |          11627 |
|     4096 |       5 |                  65 |                  79 |          15384 |
|     4096 |      25 |                  75 |                  90 |          13333 |
|     4096 |      75 |                  89 |                 129 |          11235 |
|     4096 |     150 |                  68 |                 101 |          14705 |
|     4096 |     225 |                  86 |                  96 |          11627 |
|    16384 |       0 |                 161 |                 206 |           6211 |
|    16384 |       1 |                 159 |                 192 |           6289 |
|    16384 |       5 |                 124 |                 207 |           8064 |
|    16384 |      25 |                 184 |                 296 |           5434 |
|    16384 |      75 |                 144 |                 180 |           6944 |
|    16384 |     150 |                 151 |                 197 |           6622 |
|    16384 |     225 |                 139 |                 195 |           7194 |
|    65536 |       0 |                 410 |                 449 |           2439 |
|    65536 |       1 |                 354 |                 375 |           2824 |
|    65536 |       5 |                 318 |                 443 |           3144 |
|    65536 |      25 |                 379 |                 455 |           2638 |
|    65536 |      75 |                 356 |                 440 |           2808 |
|    65536 |     150 |                 332 |                 474 |           3012 |
|    65536 |     225 |                 313 |                 386 |           3194 |
