# `tn.info` / `tn.read` — Python skin bench

Measured through the public Python API. Both paths use the same `tn.init / tn.info / tn.read` call sequence — only `TN_FORCE_PYTHON=1` differs for the 'python' rows.

- 200 emit iterations per cell
- 5 read passes per cell (per-event µs = total / event count)
- Message sizes: [64, 256, 1024, 4096, 16384, 65536]

| msg_size | path   | using_rust | info p50 µs | info p95 µs | info events/s | read p50 µs | read p95 µs | read events/s |
|---------:|:-------|:----------:|------------:|------------:|--------------:|------------:|------------:|--------------:|
|       64 | rust   |    True    |        44.9 |        62.0 |         22271 |        20.4 |        33.8 |         48924 |
|       64 | python |   False    |       189.9 |       308.2 |          5265 |       216.2 |       259.2 |          4624 |
|      256 | rust   |    True    |        42.1 |        70.3 |         23752 |        18.6 |        30.2 |         53665 |
|      256 | python |   False    |       209.4 |       437.2 |          4775 |       216.4 |       255.7 |          4622 |
|     1024 | rust   |    True    |        54.0 |        97.8 |         18518 |        20.2 |        31.0 |         49395 |
|     1024 | python |   False    |       173.4 |       293.3 |          5767 |       156.6 |       188.8 |          6386 |
|     4096 | rust   |    True    |        97.3 |       150.1 |         10277 |        41.1 |        44.5 |         24334 |
|     4096 | python |   False    |       240.7 |       327.0 |          4154 |       215.8 |       235.6 |          4634 |
|    16384 | rust   |    True    |       196.8 |       295.7 |          5081 |        87.4 |        98.6 |         11436 |
|    16384 | python |   False    |       347.5 |       535.2 |          2877 |       305.7 |       337.7 |          3271 |
|    65536 | rust   |    True    |       835.7 |      1246.8 |          1196 |       338.8 |       354.5 |          2951 |
|    65536 | python |   False    |      1236.3 |      1701.8 |           808 |       859.3 |       907.1 |          1163 |

## Rust vs Python speedup (p50)

| msg_size | info Python µs | info Rust µs | info speedup | read Python µs | read Rust µs | read speedup |
|---------:|---------------:|-------------:|-------------:|---------------:|-------------:|-------------:|
|       64 |          189.9 |         44.9 |        4.23x |          216.2 |         20.4 |       10.58x |
|      256 |          209.4 |         42.1 |        4.97x |          216.4 |         18.6 |       11.61x |
|     1024 |          173.4 |         54.0 |        3.21x |          156.6 |         20.2 |        7.73x |
|     4096 |          240.7 |         97.3 |        2.47x |          215.8 |         41.1 |        5.25x |
|    16384 |          347.5 |        196.8 |        1.77x |          305.7 |         87.4 |        3.50x |
|    65536 |         1236.3 |        835.7 |        1.48x |          859.3 |        338.8 |        2.54x |
