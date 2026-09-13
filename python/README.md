# TN-Proto

**Key access is access to encrypted data.** If your session has the required decryption keys, it can open the data. Application rules can add further restrictions when you need them.

With keys already loaded in `session` and a publication in `sealed`:

```python
data = session.unseal(
    sealed, purpose="read", decide=lambda _: True
)
```

`decide=lambda _: True` adds no application permission check. Decryption still requires the matching keys, and signature verification still runs. `purpose="read"` labels the operation; it does not grant access.

Keys control **groups of fields**. Put fields in separate groups when their access should be independent. The governed session also uses its governance-group key, which the sample session setup supplies automatically.

The wire protocol supplies encrypted groups and authenticated data. Checks for an approved writer, purpose, or contract are additional application policies. They are optional layers on top of key-based access.

## Install

```bash
python -m pip install "tn-proto==2026.9.13b4"
```

Python 3.10 or newer. Linux x86-64 and Windows x64 wheels include the Rust implementation.

## 1. Start a session

For a complete example, save the sample [agents.md](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/python/examples/getting_started/agents.md) in your working folder. It supplies the contract metadata used when creating the greeting object. This walkthrough carries that metadata without evaluating additional contract rules.

Run the following Python snippets in order, in the same process:

```python
from pathlib import Path
import tn

session = tn.Session(Path("agents.md").read_text(encoding="utf-8"))
policy = session.policy("hello.message")
```

The session has its own identity and encryption keys. This example creates fresh keys and uses them for the whole walkthrough.

## 2. Create an object and read a field

```python
message = session.create({"message": "Hello, world!"}, policy)
print(message.get("message"))
```

```text
Hello, world!
```

`create` returns a data object with an initial signed copy. `get` reads a field.

## 3. Change the field

```python
message.set("message", "Hello again!")
print(message.get("message"))
```

```text
Hello again!
```

The working data has changed. The previous signed copy still contains the original greeting.

## 4. Seal the changed object

The creating session has the publishing capabilities needed to seal its changes:

```python
publication = message.seal(
    purpose="send", to="local-reader", decide=lambda _: True
)
```

`seal` creates a new encrypted, signed publication, keeping the contract and the reference to the preceding version. Here, the callback adds no application restriction. `to` records an intended destination; it does not distribute keys or deliver the bytes.

## 5. Save and read the publication

```python
publication.write("greeting.tn")
saved = tn.GovernedObject.read("greeting.tn")
```

`write` saves the signed bytes. `read` verifies the saved publication; its business fields remain encrypted.

## 6. Unseal with the keys

The same session already holds the keys for its saved publication:

```python
received = session.unseal(
    saved, purpose="read", decide=lambda _: True
)
print(received.get("message"))
```

```text
Hello again!
```

`unseal` verifies the publication and decrypts the message. A session without the required keys cannot open it, even with `decide=lambda _: True`.

Close the session when finished:

```python
session.close()
```

The complete walkthrough is available as [hello.py](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/python/examples/getting_started/hello.py), alongside its policy file.

## Optional application rules

In the governed SDK, TN enforces **when a governance decision is made and what contract context is supplied**: receipt presents the authenticated writer, carried contracts, and requested use before opening selected business groups. The receiving application retains authority over the decision's substantive judgment.

An application may also require a particular writer, an approved purpose, or an accepted contract. Supply those checks through `decide`, or configure them once in a [workflow](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/GOVERNED_PYTHON_API.md#configure-input-output-and-attachment).

Those checks are application policy. They can refuse a use even when a key is available; they cannot open data without a key. The wire format carries contracts and provenance, but it does not execute policy prose.

## Revocation, evidence, and key services

**Revocation must not destroy required evidence.** That requirement motivates BTN's forward-only exclusion: a revoked reader is excluded from future ciphertexts produced with the updated publisher state, while retained keys can still open historical publications they covered. Keeping those publications and keys lets an application preserve readable evidence for audit and review. TN does not itself impose a retention policy or erase copies already held by a reader.

Decryption authority can be transferred through provisioned group capabilities **without requiring an online key-release service**. Applications can also use key stores and live authorization services through the [provider interfaces](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/GOVERNED_PROVIDERS.md): `KeyProvider.resolve` supplies a session's key capabilities, and `GovernanceProvider.accept` can consult current service decisions on each governed receipt. A key provider is resolved during session setup; it is not automatically called again for every unseal. `FileKeyStore` supplies the built-in persistent local option.

## Build on this example

- **Add application governance:** the [decision-context guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/GOVERNED_PYTHON_API.md#decision-contexts) shows what an evaluator can check, and [workflows](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/GOVERNED_PYTHON_API.md#configure-input-output-and-attachment) let you reuse those rules.
- **Use separate senders and readers:** the [bank/vendor example](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/python/examples/bank_vendor.py) separates identities and group keys, adds inputs totaling 35, and returns a report with the bank and vendor contracts.
- **Keep keys between runs:** the [persistent-key examples](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/python/examples/persistent_keys/README.md) cover separate setup, publishing, and reading processes. [Providers](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/GOVERNED_PYTHON_API.md#providers) connect application identity, keys, and governance.
- **Apply enterprise patterns:** the [15 examples from the book](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/python/examples/enterprise/README.md) cover request/reply, aggregation, outbox/inbox, pipelines, caches, and more.

## API and reference

The [Python API guide](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/GOVERNED_PYTHON_API.md) covers the full operation signatures, groups, decisions, providers, policy revisions, datasets, and lineage. The [object-operation reference](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/TN_VERBS_API.md) lists the verbs and their behavior.

See the [release notes](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/CHANGELOG.md), [BTN cover implementation](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/BTN_COVER.md), and [paper reproducibility review](https://github.com/cyaxios/tn-proto/blob/python-v2026.9.13b4/docs/PAPER_REPRODUCIBILITY.md) for implementation and research details.

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
