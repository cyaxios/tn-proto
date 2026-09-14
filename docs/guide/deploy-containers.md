# Running TN in containers and CI

Provision the application's identity and group keys once, then mount its
configuration and keystore into the running container. Later processes open
the same material, so their signing identity and decryption capabilities persist
across restarts.

For governed objects, the [persistent-key examples](../../python/examples/persistent_keys/README.md)
show preparation, publication, and reading in separate processes. The steps
below use the event-stream runtime and its `tn.yaml` configuration.

## Prepare the application configuration

Create an offline project in a private provisioning directory:

```bash
tn init myproject --no-link
```

This creates `.tn/myproject/tn.yaml` and its `keys/` directory. Keep the complete
project directory in private application storage. The keystore contains the
signing seed and group capabilities; the YAML's relative paths resolve from
the directory containing the file.

## Mount the project at runtime

For example, mount the provisioned project at `/run/tn` in your application
image. Run from the provisioning directory and replace `my-application` with
your image name:

```bash
docker run --mount "type=bind,src=$PWD/.tn/myproject,dst=/run/tn" my-application
```

Give the application account access to the mounted directory. The runtime
writes logs and administrative state, so the configured destinations must be
writable. Mount secrets at runtime rather than adding them to an image layer
or build context.

## Open the existing project

Python application startup and shutdown:

```python
import tn

tn.init("/run/tn/tn.yaml", link=False)
tn.info("service.started", component="worker")
tn.flush_and_close()
```

TypeScript:

```typescript
import { tn } from "@cyaxios/tn-proto";

await tn.init("/run/tn/tn.yaml", { link: false });
tn.info("service.started", { component: "worker" });
await tn.close();
```

In a service, initialize once at startup and close during shutdown. Reuse the
mount on later starts. Each separately provisioned application receives its
own identity and assigned group capabilities.

## CI and temporary storage

A CI job can restore its provisioned project through the platform's secret
storage before opening `tn.yaml`. Use a private writable directory, and retain
the state needed by later runs in the application's storage.

For independent test identities, set `TN_IDENTITY_DIR` to a temporary directory
before creating a test project. Existing projects load their signing material
from their configured keystore. Losing a temporary directory loses the keys
stored there; retain or restore the provisioned material when identity must
survive a cold start.

## Vault credentials

TypeScript's `bootstrapFromApiKey` helper consumes `TN_API_KEY`, which carries a
bootstrap signing seed and a bundle identifier. With a credential issued by
your vault and a private writable installation directory:

```typescript
import { bootstrapFromApiKey } from "@cyaxios/tn-proto";

const result = await bootstrapFromApiKey({
  vaultDid: "did:web:vault.tn-proto.org", cwd: "/run/tn-install",
});
if (result === null || result.receipt.rejectedReason) {
  throw new Error("Vault bootstrap did not install the project");
}
```

On success, open the installed project's `tn.yaml`. Replace the vault DID with
your configured service identity. The [account guide](auth.md) covers login,
backup, and restore; the [environment reference](environment-variables.md)
describes the credentials these operations consume.
