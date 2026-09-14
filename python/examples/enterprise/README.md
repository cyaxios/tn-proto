# Enterprise application patterns

These fifteen examples show how to use TN in common service and storage patterns.
They use the public object API with native sessions, assigned group keys,
configured governance decisions, and signed publications. Application code owns
calculations and database transactions.

Install the release and its test tools, then run from the repository root:

```shell
python -m pip install "tn-proto[test]==2026.9.13b5"
python -m pytest python/examples/enterprise -q
```

The tests run every pattern, exercise invalid requests and conflicting state,
and check that each pattern refuses a publication when its business-group key
does not match. Temporary SQLite databases are created by the tests.

## Start with a configured workflow

Run this from `python/examples/enterprise`:

```python
from pattern_environment import configured_example

session, work, policy = configured_example()
with session:
    source = session.create({"total_minor": 25000}, policy, group="result")
    data = work.receive(source)
    data.set("currency", "USD")
    publication = work.release(data)
    assert work.receive(publication).get("currency") == "USD"
```

`configured_example` supplies in-memory identity, key, and policy providers.
Its configured release decision checks the report recipient when present.
For persistent deployment material, see [persistent keys](../persistent_keys/README.md).

## Patterns

| Pattern | Function in `verb_patterns.py` | Application boundary |
| --- | --- | --- |
| Modular monolith | `approve` | Exact approved publication and recipient |
| Request/reply | `reply` | Selected valuation, request identity and stored response |
| Publish/subscribe | `consume` | Continuous source history and exact duplicate handling |
| Saga | `cancel` | Matching reservation and declined review |
| Outbox/inbox | `enqueue`, `deliver` | Transactional storage and accepted delivery |
| CQRS | `project` | Complete history through the requested publication |
| Backend for frontend | `analyst_view` | Contributing inputs and selected output fields |
| Aggregation | `aggregate` | Independently selected sources and complete quote set |
| Pipeline | `normalize` | Exact decimal conversion and batch completeness |
| Data product | `receive_edition` | Native dataset selection bound to the publication |
| Repository | `edit` | Signed revision and conditional database replacement |
| Archive | `archive` | Exact approved communication and retained publication |
| Cache | `cached_observation` | Selected identity and a newly evaluated use |
| Durable workflow | `finish` | Pinned checkpoint and conditional completion |
| Migration | `execute` | Accepted request/result continuity across calculations |

The pattern functions are in [verb_patterns.py](verb_patterns.py).
[verb_support.py](verb_support.py) implements business request
types and SQLite storage. [pattern_environment.py](pattern_environment.py)
configures providers; [verb_edition_fixture.py](verb_edition_fixture.py) supplies
the dataset test's signed policy revisions and catalog selection.

These examples combine signed publications and source references with
application decisions, database commits, and transport acknowledgements.
