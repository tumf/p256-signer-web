# DeFi v3 compiler input fixtures

Inputs only. These typed-data documents are read as raw bytes by
`Tests/SafeDeFiCompilerTests` (the bytes are bound into v3 commitments, so do
not reformat them). Expected digests are never stored here: the Swift tests
emit fresh vectors to `$DEFI_V3_OUTPUT_DIR/vectors.json` and
`web/registration/tests/defi-v3.test.mjs` recomputes them independently.

- `eip712-mail.json`: the EIP-712 specification example (declared domain,
  chainId 1); its published digest is a Swift known-answer check.
- `permit2-single.json`: a Permit2 `PermitSingle`-shaped request (declared
  domain without version, uint160/uint48 values in hex, number and decimal
  forms). Synthetic; not a captured production request.
- `nested-arrays.json`: derived domain with salt, nested struct arrays, fixed
  and dynamic nested arrays, uint256 max as a JSON number token, int256 min,
  int8 min, bytes/bytesN of mixed case, non-ASCII strings, and undeclared
  members including distinct NFC/NFD keys.
- `recursive-tree.json`: a recursive type definition with finite values and
  a domain without chainId/verifyingContract.
