//! Embedded public key for verifying WASM provider plugin signatures.
//!
//! The corresponding private key is stored as the `WASM_SIGNING_KEY` GitHub
//! Actions secret and is used by the CI `build-wasm` job to sign every
//! released `.wasm` file with rsign/minisign (ed25519).
//!
//! To rotate the key:
//!   1. Generate a new keypair: `rsign generate -p rosec-wasm-signing.pub -s rosec-wasm-signing.key -W`
//!   2. Replace the public key file and this constant.
//!   3. Update the `WASM_SIGNING_KEY` GitHub Actions secret.
//!   4. Re-sign all existing release artifacts with the new key.

/// The minisign public key used to verify WASM provider signatures.
/// This is the base64-encoded public key string (the second line of the .pub file).
pub const WASM_SIGNING_PUBKEY: &str = "RWTn6nvrCuaMdWkYb2aZOTsyKh1XW36iFZZGNw3kiGvJza33mB7mqXPD";
