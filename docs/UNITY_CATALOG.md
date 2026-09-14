# Use TN objects with Unity Catalog

Unity Catalog can give applications a name and storage location for a directory of encrypted TN objects. The application retrieves an object from that directory, verifies its signature, and opens its fields with its TN keys. Catalog access and the keys needed to decrypt the data are configured separately.

These examples use an open-source Unity Catalog server and local files. An external volume points to a directory containing encrypted, signed TN objects, called publications. Volumes organize files that are not represented as database tables; see the [Unity Catalog volume guide](https://docs.unitycatalog.io/usage/volumes/).

Start with a greeting, then use a named dataset edition to calculate an invoice total. Both examples use the installed TN SDK and Python's standard library.

| Example | Application code | Preparation |
| --- | --- | --- |
| Open a greeting | [unity_catalog.py](../python/examples/providers/unity_catalog.py) | Its `prepare` command creates the greeting and persistent keys. |
| Calculate from an exact dataset edition | [unity_edition.py](../python/examples/providers/unity_edition.py) | [unity_edition_setup.py](../python/examples/providers/unity_edition_setup.py) creates keys, data, a signed policy revision, and a signed edition. |

## Prepare the greeting

Install the SDK and run these commands from a checkout of this repository:

```bash
python -m pip install "tn-proto==2026.9.13b5"
python python/examples/providers/unity_catalog.py prepare ../tn-unity-demo
```

Use a new directory. Preparation refuses to overwrite an existing workspace. It creates this layout:

```text
tn-unity-demo/
  private/
    config.json
    agents.md
    keys/keystore.json
    expected-publication.json
    ...
  publications/
    greeting.tn
```

`private` contains the application's persistent signing identity, BTN keys, configuration, and the expected identifier of this exact signed object. Keep this directory accessible only to the application account. `publications/greeting.tn` is the encrypted, signed object that will be shared.

The last output line is the `file:` URI of the `publications` directory. Copy that value for the next step. Register only this directory with Unity Catalog; the private credentials stay outside the volume.

## Register the directory as a volume

Start an open-source Unity Catalog server using its [quickstart](https://docs.unitycatalog.io/quickstart/). The commands below use the local server at `http://localhost:8080` and its sample `unity.default` catalog and schema.

From the Unity Catalog checkout, replace `PUBLICATIONS_URI` with the exact URI printed by preparation:

```bash
bin/uc volume create --full_name unity.default.tn_messages --storage_location "PUBLICATIONS_URI"
bin/uc volume get --full_name unity.default.tn_messages
```

These commands create an external volume and display its metadata. Check that `storage_location` points to `tn-unity-demo/publications`. The [Unity CLI reference](https://docs.unitycatalog.io/usage/cli/) describes server selection and authentication options if your server uses different settings.

Run the TN reader where it can access the prepared local workspace. Use the same directory location in the Unity deployment; container and host paths need to agree.

## Resolve the volume and unseal the greeting

Return to the TN repository root and run:

```bash
python python/examples/providers/unity_catalog.py read ../tn-unity-demo --url http://localhost:8080 --volume unity.default.tn_messages
```

```text
Hello, world!
```

For a server that requires authentication, supply its bearer token through the reader process's `TN_UNITY_TOKEN` environment variable. Use HTTPS when sending credentials to a remote server. The example does not follow HTTP redirects.

The reader requests `/api/2.1/unity-catalog/volumes/unity.default.tn_messages` and checks the returned name and storage location. It then reads `greeting.tn`, verifies the TN signature, and compares the publication identifier with the value saved during preparation. Finally, it reopens the persistent session and unseals the greeting using its existing group keys and configured receive decision.

The expected publication identifier prevents a different, validly signed publication from silently replacing the greeting. In an application, this identifier can come from an approved job request or an accepted dataset edition. Catalog metadata supplies a location; the application's trust in a particular publication needs its own source.

## Calculate from a dataset edition

A volume locates files. A TN dataset edition also names the exact source publication, its contracts, and the uses for which it is available. This lets an application request a particular edition and check it before opening the data.

Prepare a second workspace from the TN repository root:

```bash
python python/examples/providers/unity_edition_setup.py ../tn-unity-invoice
```

This creates an invoice containing amounts `12`, `18`, and `5`. It seals the source, then signs an edition record that refers to that publication. The edition is named `closing` in the `invoices` dataset, with the permitted use `tn.UseContext("invoice-service", "accounting", "total")`.

The shared `publications` directory contains `source.tn`, `revision.tn`, and `edition.tn`. The revision records a signed version of the use contract; the edition associates that revision with the source. Keys and the identifiers the reader expects remain in `private`.

Register the printed directory URI from the Unity checkout:

```bash
bin/uc volume create --full_name unity.default.tn_invoice --storage_location "PUBLICATIONS_URI"
```

Return to the TN repository and calculate the total:

```bash
python python/examples/providers/unity_edition.py ../tn-unity-invoice --url http://localhost:8080 --volume unity.default.tn_invoice
```

```text
35
```

The reader opens its configured session and calls `resolve` to verify and admit the revision and edition. That returns `entry`, containing the exact source and a selection for the permitted use. The calculation in `unity_edition.py` is:

```python
work = session.workflow(receive="accounting", release="reporting")
data = work.unseal(entry.publication, selection=entry.selection)
total = sum(data.get("amounts"))
data.set("total", total)
data.select(["default"], fields={"default": ["total"]})
report = work.seal(data)
```

Only the total remains in the report's business data. Sealing preserves the source reference, contract, and the dataset edition used. The application saves the signed report under its publication identifier in `private/reports/` and prints the total.

`unity_edition_setup.py` contains both the preparation command and the helper functions the reader calls for configuration and admission. These checks run again when the reader runs. Shared [Unity transport helpers](../python/examples/providers/unity_client.py) handle HTTP requests, location checks, and publication identifiers for both examples.

## Catalog and publication APIs

The shared [unity_client.py](../python/examples/providers/unity_client.py) performs three operations: `lookup_volume` fetches metadata, `volume_directory` checks the requested name and prepared directory URI, and `read_publication` verifies the fixed local file and expected publication identifier. Both examples pass the resulting `GovernedObject` to the configured session.

The edition example returns a native `CatalogEntry` with its accepted `DatasetSelection`. The [local catalog example](../python/examples/providers/catalog.py) stores accepted entries in `EditionCatalog` and resolves them through `Providers.resolve(CatalogRequest(...))`. Both paths check the exact source publication and requested use before business opening.

See [management systems](MANAGEMENT_SYSTEMS.md) for identity, key, governance, and recording providers, and the [provider reference](GOVERNED_PROVIDERS.md) for their interfaces.

## Run the checks

Install `pytest` in your development environment, then run from the repository root:

```bash
python -m pytest python/tests/test_unity_catalog_example.py python/tests/test_unity_edition_example.py -q
```

The tests use a local HTTP fixture for catalog responses and real TN signatures and keys. They cover reading and calculation, refused uses, changed metadata, substituted publications, tampering, and credential handling. Use the registration and read steps above to check your Unity deployment.
