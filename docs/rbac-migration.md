# Migrating from RBAC to ReBAC

OpenFGA ships a migration toolkit that converts a classic RBAC model
(roles, permissions and subject-to-role assignments) into a ReBAC
authorization model plus relationship tuples. Everything is written through
the existing `WriteAuthorizationModel` and `Write` APIs, so migrated data is
fully compatible with every existing OpenFGA client and requires no
server-side changes.

## Components

| Package | Purpose |
| --- | --- |
| `pkg/migration/rbac` | Parses the RBAC spec and emits an OpenFGA DSL model and tuple keys |
| `pkg/migration/batchwriter` | Splits tuples into `MaxTuplesPerWrite`-sized batches and writes them concurrently via the Write API |
| `pkg/migration/client` | Small REST gateway client (store, model, write, check) used by the CLI |
| `cmd/rbacmigrate` | The `openfga rbac-migrate` CLI command |

## RBAC input format

The spec is JSON or YAML (`sigs.k8s.io/yaml` accepts both):

```yaml
roles:
  # A qualified permission "type:relation" applies only to that resource type;
  # an unqualified permission applies to every resource type in the spec.
  - name: admin
    permissions: [document:owner, document:writer, document:viewer]
  - name: viewer
    permissions: [document:viewer]

# Resources that global assignments are expanded onto. When omitted, resources
# are inferred from scoped assignments; an error is returned if global
# assignments exist and no resources can be inferred.
resources:
  - document:1
  - document:2

assignments:
  - subject: alice            # global assignment: applies to every resource
    role: admin
  - subject: platform
    kind: group               # "user" (default) or "group"
    role: viewer
  - subject: bob
    role: viewer
    resource: document:1      # scoped assignment
```

## Generated ReBAC model

The converter uses the role-as-group pattern:

```text
type role
  relations
    define assignee: [user, group#assignee]

type document
  relations
    define admin_binding:  [user, group#assignee, role#assignee]
    define viewer_binding: [user, group#assignee, role#assignee]
    define owner:  admin_binding
    define viewer: admin_binding or viewer_binding
```

- A scoped assignment becomes `<resource>#<role>_binding@<subject>`.
- A global assignment stores subjects on `role:<name>#assignee` and links the
  role object into the binding relation of each resource once, so a global
  role costs one link tuple per resource instead of one tuple per subject per
  resource.
- Group subjects are referenced as `group:<id>#assignee`, matching the
  `group#assignee` type restriction; group membership itself is modeled with
  `group:<id>#assignee@user:<id>` tuples.

## Running the CLI

Dry-run (writes only the DSL model and a JSON report, no server calls):

```bash
openfga rbac-migrate \
  --input rbac.yaml \
  --model-output authorization-model.fga
```

Live migration through the public REST gateway:

```bash
openfga rbac-migrate \
  --input rbac.yaml \
  --api-url http://localhost:8080 \
  --store-name rbac-migration \
  --batch-size 100 \
  --max-concurrent-writes 8 \
  --ignore-duplicates
```

`--ignore-duplicates` sets `on_duplicate=ignore` on every Write request,
which makes re-running a migration idempotent. Use `--store-id` to migrate
into an existing store instead of creating one.

## Embedding the packages

```go
result, err := rbac.Migrate(spec)
// result.DSL, result.Model and result.TupleKeys are ready to use.

writer := batchwriter.New(openfgaServer, storeID, modelID,
    batchwriter.WithBatchSize(100),
    batchwriter.WithMaxConcurrentWrites(8),
    batchwriter.WithIgnoreDuplicates(),
)
report, err := writer.Write(ctx, result.TupleKeys)
```

`batchwriter.TupleWriter` is satisfied by both the in-process
`*server.Server` and the generated gRPC client.
