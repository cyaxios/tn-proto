# Persistent BTN and JWE examples

The SDK must expose `tn.providers.FileKeyStore`. Each command starts a separate process:

```shell
python -B setup.py btn-demo --cipher btn
python -B hello_btn.py btn-demo publish
python -B hello_btn.py btn-demo read

python -B setup.py jwe-demo --cipher jwe
python -B hello_jwe.py jwe-demo publish
python -B hello_jwe.py jwe-demo read
```

Both readers print `Hello, world!`. Setup refuses to replace an existing installation. Publication and reading reopen the saved credentials; they never generate them.

Source files: [setup.py](setup.py), [configuration.py](configuration.py), [workflow.py](workflow.py), [hello_btn.py](hello_btn.py), [hello_jwe.py](hello_jwe.py), and [agents.md](agents.md).

Each installation contains `config.json`, `agents.md`, `keys/keystore.json`, `hello.tn`, `creations.jsonl` and `releases.jsonl`. The keystore holds secret raw credentials. Unix mode is 0600; Windows uses the containing directory ACL. Keep generated installations outside published source folders.

## HIBE

```shell
python -B setup.py hibe-demo --cipher hibe
python -B hello_hibe.py hibe-demo publish
python -B hello_hibe.py hibe-demo read
python -B hibe_delegation.py
```

The persistent example saves scoped keys and public parameters. The delegation example uses the Rust-backed HIBE primitives to issue a parent grant, delegate a child, and assign it through the native group provider.
