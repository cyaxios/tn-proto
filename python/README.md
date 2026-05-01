# tn-protocol

TestigoNodo (TN) Python SDK — attested logging with JWE + btn ciphers.

```bash
pip install tn-protocol
```

```python
import tn

tn.init("./tn.yaml")
tn.info("order.created", order_id="A100", amount=4999)

for entry in tn.read():
    print(entry["event_type"], entry.get("order_id"))

tn.flush_and_close()
```

Source, docs, and issue tracker: https://github.com/cyaxios/tn-proto

License: Apache-2.0
