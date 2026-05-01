# 1 KB message — where does the time go?

```

=== Per-event breakdown for 1024-byte messages ===

Phase                                          |   p50 us |   p95 us |   events/s
----------------------------------------------------------------------------------
tn.info (full skin)                            |     41.8 |     68.7 |      23923
PyRuntime.emit (no tn.info wrapper)            |     40.9 |     64.2 |      24449
tn.read (full skin, list()'d)                  |     22.4 |     31.5 |      44686
PyRuntime.read (PyO3 call + PyO3 dict build)   |     20.0 |     54.7 |      49989
PyO3 call overhead (rt.did())                  |      0.1 |      0.1 |    9999923

=== Derived ===

tn.info wrapper overhead         :    0.9 us
  (Python: context merge, DispatchRuntime hop, kwargs -> dict)

_rust_entries_with_valid wrap    :    2.4 us/event
  (Python: chain walk + build 'valid' dict per entry, generator yield)

PyO3 minimal call overhead       :    0.1 us

Accounting (1 KB, Rust path):
  direct PyRuntime.emit          :   40.9 us
  + tn.info wrapper              : +  0.9 us
  = tn.info full skin            :   41.8 us

  direct PyRuntime.read / entry  :   20.0 us
  + _rust_entries_with_valid     : +  2.4 us
  = tn.read full skin / entry    :   22.4 us

Note: PyRuntime.read includes PyO3 dict-building for every envelope and
plaintext field, which is substantial for the 'read' path. In contrast,
emit only builds a 3-key receipt dict on return.
```
