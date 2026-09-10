# Native governed workflow fixture, M1

`manifest.json` retains eleven ordinary signed TN publications: two policy
revisions, two edition records, their two equally valued source publications,
the joined release, the DeepVest-shaped release, and three deliberately invalid
lineage declarations. The latter have valid TN hashes and signatures; admission
must reject their omitted contracts, omitted bindings, or unreachable origins.

The fixture contains **public test-only key material**. The Ed25519 seed is the
documented constant `51` repeated 32 times; BTN material is generated exclusively
for this fixture. Never provision these keys outside a test environment.

Run these commands from the repository root:

```powershell
cargo run -p tn-core --example governed_fixture_manifest --locked -- --verify tests/fixtures/governed/v1/manifest.json
cargo run -p tn-core --example governed_fixture_manifest --locked -- --materialize tests/fixtures/governed/v1/manifest.json target/m1-fixture-session
.venv/Scripts/python.exe -m pytest python/tests/test_governed_m1_fixture.py -q
```

Materialization requires a new directory. It writes `tn.yaml`, policy text, and
the fixture's BTN/Ed25519 files, then verifies the configured native session can
open a retained publication. Python can load that same configuration with
`tn.Session.from_config("target/m1-fixture-session/tn.yaml")`. Native consumers can
instead decode each group's `reader_kit_base64` with `BtnReaderCipher` and create
a `GovernedReader`. Publisher state is included for test release checks.

Interoperability consumers must retain `publications[name].wire` exactly, compare
its parsed identity with `object_id`, and admit both signed policy revisions and
edition records through their native types. Select each edition by its exact
edition-record identity under `uses.source`. `earlier` and `later` are explicit
labels, not ordering rules. Both editions carry the same synthetic wealth path,
but have distinct signed sources and policy revisions.

`expected_releases` pins all contributing revision identities, dataset bindings,
immediate parents, reachable signed object identities, and decrypted finance
content. The joined object names both source publications; the DeepVest-shaped
object names only the joined object as its immediate parent. Send
`publications.deepvest.wire` unchanged to the model boundary under `uses.model`.

`cases` lists fifteen accepted/refused receipt scenarios with use, selected
groups, callback behavior, callback count, and business-decrypt count. Derived
receipt composes lineage verification, catalog acceptance, and exact writer
trust before opening business data. Every refusal expects zero business decrypts.
The exporter replays these checks before writing; `--verify` replays them from
the retained bytes without regenerating publications or keys.

The Python consumer checks the same signed identities, both release graphs,
selected bindings, fifteen admission outcomes, callback counts, and exception
identity. Business-decrypt counts are measured by the native exporter/replayer's
counting reader; Python's fixture test delegates opening to the installed SDK.

To regenerate intentionally:

```powershell
cargo run -p tn-core --example governed_fixture_manifest --locked -- --export tests/fixtures/governed/v1/manifest.json
```

Regeneration creates fresh randomized BTN ciphertexts, timestamps, and publication
identities. Reproducibility means replaying the retained manifest's exact bytes,
not expecting a new export to have identical hashes. The producer record pins
the exporting example's source SHA-256. Review and retain the new manifest as a
unit whenever regenerating.

The calculation is synthetic fixture arithmetic (`max_drawdown = 0.25` for
`[100, 120, 90, 135]`), not a DeepVest-engine or model execution claim. The edition
artifact digests are structural placeholders, not downloadable OPA modules.
Connected execution and actual evaluator-artifact loading are later milestones.
