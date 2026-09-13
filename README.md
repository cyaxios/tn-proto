# TN-Proto

Create encrypted, signed data objects in Python. Each object carries a use contract and retains the sources your application records as it works with the data.

Start with a greeting. The examples below build on one another, one operation at a time.

## Install

```bash
python -m pip install "tn-proto==2026.9.13b3"
```

Python 3.10 or newer. Linux x86-64 and Windows x64 wheels include the Rust implementation.

## 1. Start a session

Save the sample [agents.md](python/examples/getting_started/agents.md) in your working folder. It contains a contract named `hello.message` for displaying greetings.

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

## 4. Define the approval rule

Before opening or publishing data, the application makes a decision. For this example, accept our own writer and exactly the contract we selected:

```python
def trusted_message(context):
    return (
        context.writer == session.did
        and len(context.policies) == 1
        and context.policies[0].matches_contract(policy)
    )
```

TN supplies the writer and carried contracts to this function. The application provides the rule; the text in `agents.md` does not execute itself.

## 5. Seal the changed object

Name the application, purpose, and operation with `UseContext`. Then approve this publication for its intended destination:

```python
publish_use = tn.UseContext("hello", "greeting", "publish")
publication = message.seal(
    use=publish_use, to="local-reader",
    decide=lambda context: trusted_message(context)
    and context.use_context == publish_use
    and context.destination == "local-reader",
)
```

`seal` evaluates the decision and creates a new encrypted, signed publication. It keeps the contract and the reference to the preceding version. The destination is part of the approval; your application chooses how to deliver the bytes.

## 6. Save and read the publication

```python
publication.write("greeting.tn")
saved = tn.GovernedObject.read("greeting.tn")
```

`write` saves the signed bytes. `read` verifies the saved publication; its business fields remain encrypted.

## 7. Unseal it for an approved use

The same session can open its saved publication. Approve the writer, contract, and requested reading use:

```python
read_use = tn.UseContext("hello", "greeting", "read")
received = session.unseal(
    saved, use=read_use,
    decide=lambda context: trusted_message(context)
    and context.use_context == read_use,
)
print(received.get("message"))
```

```text
Hello again!
```

`unseal` verifies the publication, runs the approval rule, and decrypts the message using the session's keys. A refused decision or a missing key stops it from returning the business data.

Close the session when finished:

```python
session.close()
```

The complete walkthrough is available as [hello.py](python/examples/getting_started/hello.py), alongside its policy file.

## Build on this example

- **Reuse the same rules:** configure a [workflow](docs/GOVERNED_PYTHON_API.md#configure-input-output-and-attachment) once, then call `work.unseal(...)` and `work.seal(...)` in application code.
- **Use separate senders and readers:** the [bank/vendor example](python/examples/bank_vendor.py) separates identities and group keys, adds inputs totaling 35, and returns a report with the bank and vendor contracts.
- **Keep keys between runs:** the [persistent-key examples](python/examples/persistent_keys/README.md) cover separate setup, publishing, and reading processes. [Providers](docs/GOVERNED_PYTHON_API.md#providers) connect application identity, keys, and governance.
- **Apply enterprise patterns:** the [15 examples from the book](python/examples/enterprise/README.md) cover request/reply, aggregation, outbox/inbox, pipelines, caches, and more.

## API and reference

The [Python API guide](docs/GOVERNED_PYTHON_API.md) covers the full operation signatures, groups, decisions, providers, policy revisions, datasets, and lineage. The [object-operation reference](docs/TN_VERBS_API.md) lists the verbs and their behavior.

See the [release notes](CHANGELOG.md), [BTN cover implementation](docs/BTN_COVER.md), and [paper reproducibility review](docs/PAPER_REPRODUCIBILITY.md) for implementation and research details.

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
