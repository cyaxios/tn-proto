# Find and open a TN object with Unity Catalog

Unity Catalog can give applications a name and storage location for a directory of encrypted TN objects. The application retrieves an object from that directory, verifies its signature, and opens its fields with its TN keys. Catalog access and the keys needed to decrypt the data are configured separately.

This walkthrough uses an open-source Unity Catalog server and local files. An external volume points to a directory containing one encrypted, signed greeting, called a publication. Volumes organize files that are not represented as database tables; see the [Unity Catalog volume guide](https://docs.unitycatalog.io/usage/volumes/).

The executable is [unity_catalog.py](../python/examples/providers/unity_catalog.py). It uses the Python standard library for the catalog request and the installed TN SDK for signing and encryption.

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

This example uses local files, so run the TN reader where it can access the prepared workspace. For a local Unity deployment, use a directory location that is valid in that deployment as well. Container paths and host paths need to agree. Cloud object storage requires a storage client and credentials in the application; the example only reads the prepared local file.

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

## Connect it to a larger application

The example opens a local file after checking the volume metadata. To use remote storage, retrieve the stored TN bytes with your storage client and pass them to `tn.GovernedObject.parse`. The session still performs the same unseal operation. Share encrypted publications, and provision each reader's TN keys through your chosen key provider.

For datasets with named editions and approved uses, the [dataset catalog example](../python/examples/providers/catalog.py) builds an accepted `DatasetSelection` and a `CatalogEntry`. A provider that combines this selection with Unity metadata can return the exact publication for a `CatalogRequest`. The volume lookup in this walkthrough does not construct an edition selection.

See [management systems](MANAGEMENT_SYSTEMS.md) for identity, key, governance, and recording providers, and the [provider reference](GOVERNED_PROVIDERS.md) for their interfaces.

## Run the checks

Install `pytest` in your development environment, then run from the repository root:

```bash
python -m pytest python/tests/test_unity_catalog_example.py -q
```

The tests use a local HTTP fixture for catalog responses and real TN signatures and keys. They check the successful read, rejected metadata changes, publication substitution, tampering, and credential handling. They do not start or validate a live Unity Catalog deployment; use the registration and read steps above to check your server.
