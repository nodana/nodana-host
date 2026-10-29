# Host controller development

Install Rust and the OpenSSL development libraries (including pkg-config), then
from the repository root run:

```sh
export NODANA_PUBLIC_DOMAIN=staging.nodana.app
cargo fmt --manifest-path host/controller/Cargo.toml --check
cargo check --manifest-path host/controller/Cargo.toml --locked
cargo test --manifest-path host/controller/Cargo.toml --locked
```

Validation uses the staging domain for synthetic test identities and disposable
local TLS servers. The public fixture contains AWS-signed evidence, with tests
evaluating it at its recorded capture time. These tests do not contact AWS.

## Create an invoice through the control API

An API-role mTLS client can call
`POST /v1/deployments/{deploymentId}/invoices` for a ready deployment with JSON:

```json
{
  "amountSat": 1000,
  "description": "Order 1042",
  "expirySeconds": 600,
  "externalId": "order-1042"
}
```

`amountSat` and `description` are required. The amount must be a positive integer
no greater than 9,007,199,254,740,991. Descriptions and optional external IDs must
contain non-whitespace text and be at most 128 characters. Optional
`expirySeconds` must be a positive 32-bit unsigned integer; omission uses
Phoenixd's default. Unknown fields are rejected, including webhook overrides.

The response contains `amountSat`, `paymentHash` and `serialized` (the BOLT11
invoice). The controller uses the node's restricted credential internally and
retains its configured webhook destination. Invalid inputs return 400, a
deployment that is not ready returns 409, and upstream failures or malformed
responses return 503. Existing control identity checks apply.

Creation is not idempotent: `externalId` is a correlation reference, not a
deduplication key. A timeout can occur after Phoenixd creates the invoice;
reconcile incoming payment records before deciding whether to create another.

## Build the controller

To build a controller, explicitly supply its deployment domain:

```sh
NODANA_PUBLIC_DOMAIN=staging.nodana.app cargo build \
  --manifest-path host/controller/Cargo.toml --locked --release
```

The controller's package version is in `host/controller/Cargo.toml`. It is
independent of the Phoenixd bundle version. The private AWS image workflow pins
an exact commit of this repository, builds the controller into the host image,
and records the source commit and staged file hashes in image provenance.

Bundle verification runs inside the Rust controller. The signing public key,
download origin, domain and public control identities are image inputs supplied
by the environment. Private keys are not build inputs.

The controller runs once per host. A node update changes that node's selected
bundle without replacing the controller. Controller changes require a new host
image and separate host-attestation approval.

Host capacity is an API-managed operating setting, not an image input. A fresh
controller accepts no new deployments until the API configures a positive limit
with mTLS `POST /v1/capacity` and `{"capacity":8}`. The controller persists it in
its control database and reports it through `GET /v1/resources`. Limit changes
and slot reservations share the database lock. Lowering the limit preserves
existing slots and nodes, and blocks new allocations until usage falls below it.
Validation only requires a positive count fitting the node TCP port range
(20000–65535). Existing-node lifecycle operations do not depend on free capacity.
