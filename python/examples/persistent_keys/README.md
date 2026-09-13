# Persistent BTN and JWE examples

Install an SDK version that exposes `tn.providers.FileKeyStore`, then run these commands from the repository root. Each command starts a separate process; the generated installations go beside the checkout:

```shell
python -B python/examples/persistent_keys/setup.py ../tn-btn-demo --cipher btn
python -B python/examples/persistent_keys/hello_btn.py ../tn-btn-demo publish
python -B python/examples/persistent_keys/hello_btn.py ../tn-btn-demo read

python -B python/examples/persistent_keys/setup.py ../tn-jwe-demo --cipher jwe
python -B python/examples/persistent_keys/hello_jwe.py ../tn-jwe-demo publish
python -B python/examples/persistent_keys/hello_jwe.py ../tn-jwe-demo read
```

Both readers print `Hello, world!`. Setup refuses to replace an existing installation. Publication and reading reopen the saved credentials; they never generate them.

Source files: [setup.py](setup.py), [configuration.py](configuration.py), [workflow.py](workflow.py), [hello_btn.py](hello_btn.py), [hello_jwe.py](hello_jwe.py), and [agents.md](agents.md).

Each installation contains `config.json`, `agents.md`, `keys/keystore.json`, `hello.tn`, `creations.jsonl` and `releases.jsonl`. The keystore holds secret raw credentials. Unix mode is 0600; Windows uses the containing directory ACL. Keep generated installations outside published source folders.

## HIBE

```shell
python -B python/examples/persistent_keys/setup.py ../tn-hibe-demo --cipher hibe
python -B python/examples/persistent_keys/hello_hibe.py ../tn-hibe-demo publish
python -B python/examples/persistent_keys/hello_hibe.py ../tn-hibe-demo read
python -B python/examples/persistent_keys/hibe_delegation.py
```

The persistent example saves scoped keys and public parameters. The delegation example uses the Rust-backed HIBE primitives to issue a parent grant, delegate a child, and assign it through the native group provider.
