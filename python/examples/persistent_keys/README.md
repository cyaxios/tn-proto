# Persistent BTN, JWE, and HIBE examples

Install `tn-proto==2026.9.14b1`, then run these commands from the repository root. Each command starts a separate process; the generated installations go beside the checkout:

```shell
python -B python/examples/persistent_keys/setup.py ../tn-btn-demo --cipher btn
python -B python/examples/persistent_keys/hello_btn.py ../tn-btn-demo publish
python -B python/examples/persistent_keys/hello_btn.py ../tn-btn-demo read

python -B python/examples/persistent_keys/setup.py ../tn-jwe-demo --cipher jwe
python -B python/examples/persistent_keys/hello_jwe.py ../tn-jwe-demo publish
python -B python/examples/persistent_keys/hello_jwe.py ../tn-jwe-demo read
```

Both readers print `Hello, world!`. Use a new directory for setup. Publication and reading reopen the saved identity and group capabilities.

Source files: [setup.py](setup.py), [configuration.py](configuration.py), [workflow.py](workflow.py), [hello_btn.py](hello_btn.py), [hello_jwe.py](hello_jwe.py), and [agents.md](agents.md).

Each installation contains `config.json`, `agents.md`, `keys/keystore.json`, `hello.tn`, `creations.jsonl` and `releases.jsonl`. Store the installation in a private application directory: Unix keystore creation uses mode `0600`, and Windows uses the containing directory's ACL. Share `hello.tn` with its intended readers.

`FileKeyStore` supplies both identity and key resolution. [configuration.py](configuration.py) calls `FileKeyStore.open`, checks the saved cipher and groups, and passes the store to both slots in `Providers(store, store, governance, registers=registers)`. The session signs and opens publications with that material in Rust.

## HIBE

```shell
python -B python/examples/persistent_keys/setup.py ../tn-hibe-demo --cipher hibe
python -B python/examples/persistent_keys/hello_hibe.py ../tn-hibe-demo publish
python -B python/examples/persistent_keys/hello_hibe.py ../tn-hibe-demo read
python -B python/examples/persistent_keys/hibe_delegation.py
```

The HIBE reader also prints `Hello, world!`. Its persistent store saves scoped keys and public parameters. The delegation example uses the Rust-backed HIBE primitives to issue a parent grant, delegate a child, and assign it through `GroupCapability.hibe`. It opens the greeting with the child grant and checks that a sibling grant is refused.
