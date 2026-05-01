# Signed vs unsigned emit — Rust path via Python skin

- 500 iterations per cell
- Measured through `tn.info(...)` — the public Python API
- signed = default; unsigned = `tn.set_signing(False)` for the session; per-call = `_sign=False` kwarg
- Delta column = signed p50 minus unsigned p50 = cost of the Ed25519 signature

| msg_size | signed p50 us | unsigned p50 us | per-call p50 us | delta us | saved % | signed events/s | unsigned events/s |
|---------:|--------------:|----------------:|----------------:|---------:|--------:|----------------:|------------------:|
|       64 |          29.4 |            14.7 |            14.4 |    +14.7 |   50.0% |           34013 |             68027 |
|      256 |          33.7 |            16.6 |            17.2 |    +17.1 |   50.7% |           29673 |             60240 |
|     1024 |          41.4 |            26.1 |            25.3 |    +15.3 |   37.0% |           24154 |             38314 |
|     4096 |          72.5 |            53.3 |            55.9 |    +19.2 |   26.5% |           13793 |             18761 |
|    16384 |         178.2 |           167.6 |           165.1 |    +10.6 |    5.9% |            5611 |              5966 |
|    65536 |         633.9 |           633.7 |           624.8 |     +0.2 |    0.0% |            1577 |              1578 |

## Notes

- Per-call `_sign=False` matches session-level `tn.set_signing(False)` within noise — they route to the same Rust code path.
- Absolute savings hold roughly constant across sizes (signing is fixed-cost, size-independent).
- Relative savings shrink as payloads grow because AEAD + JSON serialize start to dominate.
- Small events (<256 B) see the biggest proportional win — exactly the OTEL/tracing sweet spot.