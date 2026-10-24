# Nodana host controller

Public Rust source for the controller that manages Phoenixd nodes on a Nodana
host, including protected startup, bundle verification and certificate peer
attestation.

One controller runs per host. It manages a separate process, UID and persistent
wallet directory for each node. The per-node software bundle is built separately
in [nodana-phoenixd](https://github.com/nodana/nodana-phoenixd).

To inspect how a running bundle is identified, start with
[`runtime.rs`](host/controller/src/runtime.rs). It verifies the installed bundle
and checks the live process before reporting its identity. Attestation response
generation is in [`host.rs`](host/controller/src/host.rs) and
[`server.rs`](host/controller/src/server.rs). The certificate-peer verifier is
[`attestation.rs`](host/controller/src/attestation.rs); bundle validation and
installation are in [`bundle.rs`](host/controller/src/bundle.rs).

For build inputs and local verification, see [development](docs/development.md).
