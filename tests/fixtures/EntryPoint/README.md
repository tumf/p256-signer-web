# EntryPoint v0.7 runtime authority

This is a frozen historical Polygon chain137 runtime snapshot, not a mock EntryPoint. `entrypoint-runtime.json` retains its original capture metadata and bytes. `manifest.json` fixes snapshot/runtime/license hashes, code identity and source revision; validate all before use. Do not overwrite or recapture it during tests.

- Canonical address: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`.
- Runtime Keccak256: `0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58`, 16035 bytes.
- Historical block: 95865420, hash `0x856dc2ef6444dc6de29b3e2aa7feaae62bd1e4d68d63ed0eb7c71ef14c3ba88f`.
- Source authority: account-abstraction v0.7.0 at revision `7af70c8993a6f42973f520ae0752386a5032abe7`, `contracts/core/EntryPoint.sol`.
- Corresponding upstream source: https://github.com/eth-infinitism/account-abstraction/tree/7af70c8993a6f42973f520ae0752386a5032abe7

SPDX is `GPL-3.0`; the complete license is `LICENSE-GPL-3.0`. Do not substitute the package metadata's ISC label. Runtime tests only install these bytes into a private loopback EVM. They must not include this runtime in browser assets or deployment bundles. Public distribution of the GPL artifact requires corresponding-source compliance; this private local fixture is not a release authorization.

The artifact contains immutable senderCreator data. Tests admit empty initCode only, and do not claim etching a freshly built EntryPoint is equivalent. The capture is operator-trusted provenance, not a verified reproducible compiler/source-to-bytecode attestation. Source revision supplies ABI/semantic authority, while the installed runtime itself supplies execution behavior. An offline local installation is not a Polygon fork, public RPC observation, device signature or product-deployment proof.
