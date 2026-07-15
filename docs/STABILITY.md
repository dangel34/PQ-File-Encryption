# pqfile API Stability Policy

This document defines the stability guarantee for the `pqfile` Rust library crate,
effective from version **4.0.0**.

---

## Stability guarantee

For any item listed in the **Stable surface** section below, we commit to the
following across all **4.x** minor releases:

- **No removals.** A public function, type, constant, or trait that exists in
  4.0.0 will not be removed before 5.0.0.
- **No renames.** Public items will not be renamed without a deprecation period
  followed by a major version bump.
- **No signature breaks.** Function parameters will not be reordered, removed, or
  have their types changed in a backward-incompatible way.
- **Additive changes only.** New items may be added to modules at any time. New
  variants may be added to `#[non_exhaustive]` enums without a major version bump.

A **2.0.0** (major) release is required before any breaking change to the stable
surface.

---

## Stable surface

### Core modules

| Module | What is stable |
|--------|----------------|
| `pqfile::encrypt` | `encrypt_bytes`, `encrypt_stream`, `encrypt_stream_multi`, `encrypt_stream_multi_anon`, `encrypt_stream_multi_anon_padded`, `encrypt_stream_compressed`, `encrypt_stream_parallel`, `encrypt_stream_pipelined`, `encrypt_stream_passphrase`, `encrypt_stream_passphrase_with_params`, `encrypt_stream_passphrase_keyfile`, `encrypt_stream_passphrase_keyfile_with_params`, `encrypt_stream_passphrase_fido2`, `encrypt_stream_passphrase_fido2_with_params`, `encrypt_stream_passphrase_webauthn_prf`, `encrypt_stream_passphrase_webauthn_prf_with_params`, `encrypt_stream_stealth`, `encrypt_mmap` (native only) |
| `pqfile::decrypt` | `decrypt_bytes`, `decrypt_stream`, `decrypt_stream_parallel`, `decrypt_stream_passphrase`, `decrypt_stream_passphrase_with_limits`, `decrypt_stream_passphrase_keyfile`, `decrypt_stream_passphrase_keyfile_with_limits`, `decrypt_stream_passphrase_fido2`, `decrypt_stream_passphrase_fido2_with_limits`, `decrypt_stream_passphrase_webauthn_prf`, `decrypt_stream_passphrase_webauthn_prf_with_limits`, `decrypt_stream_stealth` |
| `pqfile::sign` | `sign_keygen`, `sign_keygen_bytes`, `sign_keygen_hardware`, `sign_keygen_hardware_bytes`, `sign_bytes`, `sign_file`, `verify_bytes`, `verify_file`, `encode_sig_pem`, `decode_sig_pem`, `default_sig_path`, `SignKeygenResult` |
| `pqfile::signcrypt` | `signcrypt`, `signcrypt_bytes`, `signdecrypt` |
| `pqfile::keygen` | `keygen`, `keygen_bytes`, `keygen_bytes_hybrid_768`, `keygen_hardware`, `keygen_bytes_hardware`, `keygen_bytes_hardware_hybrid`, `is_encrypted_key`, `is_hardware_key`, `fingerprint`, `fingerprint_pem` |
| `pqfile::keys` | `PqfPublicKey`, `PqfPrivateKey`, `PqfSigningKey`, `PqfVerifyingKey` and all their methods |
| `pqfile::inspect` | `inspect_stream`, `PqfHeaderInfo`, `RecipientInfo`, `PqfInfo` |
| `pqfile::reader` | `PqfReader`, `PqfInfo` |
| `pqfile::writer` | `PqfWriter` |
| `pqfile::repassphrase` | `repassphrase`, `repassphrase_file`, `RepassphraseResult` |
| `pqfile::hardware` | `HW_TAG_*` constants, `is_hardware_tag`, `default_backend_id` |
| `pqfile::hardware::stub` | `BACKEND_CREDENTIAL_STORE`, `BACKEND_PKCS11` |
| `pqfile::async_io` *(feature = "async")* | `encrypt_stream_async`, `decrypt_stream_async`, `AsyncPqfWriter` |
| `pqfile::tlock` *(feature = "tlock")* | `encrypt_stream_tlock`, `decrypt_stream_tlock`, `round_for_target_time`, `quicknet`, `TlockChain` |
| `pqfile::archive` | `create`, `extract`, `list`, `create_from_memory`, `extract_to_memory`, `ArchiveEntry` |
| `pqfile::shamir` | `split_key`, `reconstruct_key`, `write_shares`, `SplitResult` |
| `pqfile::rekey` | `rekey_stream` |
| `pqfile::padding` | `padme_length`, `PadmeReader`, `TruncatingWriter` |
| `pqfile::add_recipient` | `add_recipient_stream`, `AddRecipientInfo` |
| `pqfile::revoke` | `revoke_key`, `check_not_revoked`, `revoked_path_for` |
| `pqfile::shred` | `shred_file` |
| `pqfile::error` | `PqfileError` (all variants; new variants may be added in minor releases) |

### Format constants

All public constants in `pqfile::format` (version bytes, `VERSION_AUTH_BIT`, KEM variant IDs, size constants, `adaptive_chunk_size`) are stable. Their **numeric values** will not change. The helper functions `format::version_layout` and `format::is_header_authenticated` are also stable.

### Crate-level re-exports

The following items re-exported at the crate root are stable:

- `pqfile::PqfileError`
- `pqfile::CHUNK_SIZE`
- `pqfile::inspect_stream`, `pqfile::PqfHeaderInfo`, `pqfile::RecipientInfo`
- `pqfile::PqfPublicKey`, `pqfile::PqfPrivateKey`, `pqfile::PqfSigningKey`, `pqfile::PqfVerifyingKey`
- `pqfile::PqfReader`, `pqfile::PqfInfo`
- `pqfile::PqfWriter`

---

## Not covered by this guarantee

The following are **not** part of the stable surface and may change in minor releases:

- **Internal helpers** (`pub(crate)` items, items in `pqfile::passphrase`).
- **Struct field additions.** All public structs and enums are `#[non_exhaustive]`.
  Existing fields will not be removed or renamed, but new fields may be added.
  Always construct structs via constructors (functions), not struct literals, to
  remain forward-compatible.
- **`pqfile::format` internal structs** (`PqfHeader`, `PqfHeaderV4`, etc.). These
  are public for technical reasons but are not part of the high-level stable API.
- **Format file versions.** New `.pqf` format versions may be added (v9, v10, …)
  in minor releases. Old versions will continue to be readable.
- **Hardware backend details.** The `credential_store` module inside `hardware` is
  an implementation detail. Its specific behaviour (which OS store is used, what
  account naming scheme is applied) may change as platform support evolves.

---

## Versioning

The `pqfile` library crate uses [Semantic Versioning](https://semver.org/):

- **Patch** (4.0.x): bug fixes that do not change the public API or file format.
- **Minor** (4.x.0): additive changes (new functions, new error variants, new
  format versions for read and write). All existing code continues to compile.
- **Major** (x.0.0): any breaking change to the stable surface listed above, or
  removal of support for an existing file format version.

The `pqfile` library, `pqfile-cli`, and `pqfile-gui` all share the same version
sequence (4.x). A major version bump applies to all three simultaneously.

---

## Encrypted key format compatibility

Keys encrypted with **pqfile < 4.0** (Argon2id p=1) are not loadable by the
standard decrypt path in 4.0+. Use `pqfile repassphrase --from-legacy` once to
migrate existing keys to p=4 before upgrading. After migration, all existing
`.pqf` files remain fully compatible.
