# pqfile JSON Error Codes

When `--json` is passed to the CLI, every error response includes a numeric `code` field alongside the human-readable `message`:

```json
{"status":"error","code":7,"message":"decryption failure: authentication tag mismatch"}
```

Scripts should branch on `code`, not on `message` (which may change). New error variants are always assigned new codes; existing codes are never reused or reassigned.

Code `0` is a catch-all for errors that do not map to a known variant (should not occur in practice).

## Code Table

| Code | `PqfileError` variant | Meaning |
|------|----------------------|---------|
| 0 | *(unknown)* | Unrecognised error variant (catch-all) |
| 1 | `Io` | Underlying I/O error (read/write/open failure) |
| 2 | `InvalidMagic` | File does not start with `PQFL` magic bytes |
| 3 | `UnsupportedVersion` | Format version byte is not recognised |
| 4 | `UnsupportedKem` | KEM variant field is not recognised |
| 5 | `KemVariantMismatch` | Private key uses a different KEM variant than the file |
| 6 | `EncryptionFailure` | KEM encapsulation or AEAD encryption failed |
| 7 | `DecryptionFailure` | AEAD authentication tag mismatch; file may be corrupt or tampered |
| 8 | `InvalidPem` | PEM data could not be parsed |
| 9 | `InvalidKeyLength` | Key material has an unexpected byte length |
| 10 | `OutputExists` | Output file already exists; pass `--force` to overwrite |
| 11 | `WrongPassphrase` | Passphrase did not decrypt the key |
| 12 | `PassphraseRequired` | Key is passphrase-protected but no passphrase was supplied |
| 13 | `PassphraseMismatch` | New-passphrase confirmation did not match |
| 14 | `InvalidSignature` | Signature bytes are malformed |
| 15 | `SignatureVerificationFailed` | Signature is well-formed but does not verify |
| 16 | `NoMatchingRecipient` | No recipient slot in the file matched the supplied private key |
| 17 | `KeyRevoked` | Key has been explicitly revoked |
| 18 | `CompressionNotSupported` | Compressed format (v6) requires a build feature not present |
| 19 | `LegacyKeyFormat` | Key was encrypted with legacy Argon2id parameters (p=1); run `repassphrase --from-legacy` |
| 20 | `ShareVerificationFailed` | Shamir share fingerprints did not agree; wrong shares or wrong key |
| 21 | `Truncated` | Stream ended before the final authenticated chunk; re-download the file |
| 22 | `KdfLimitExceeded` | v10 file's Argon2 parameters exceed the configured ceiling; raise `--max-kdf-mem`/`--max-kdf-time` if the file is trusted |
| 23 | `KeyfileRequired` | v10 file was encrypted with a keyfile second factor; pass `--keyfile <PATH>` |
| 24 | `KeyfileNotRequired` | `--keyfile` was passed but the file was not encrypted with one; remove the flag |
| 25 | `UnsupportedHeaderFlags` | v10 header carries flag bits this build does not understand; upgrade pqfile |
| 26 | `Fido2Required` | v10 file was encrypted with a FIDO2 hardware token second factor; pass `--fido2 <ENROLLMENT_FILE>` |
| 27 | `Fido2NotRequired` | `--fido2` was passed but the file was not encrypted with one (or uses `--keyfile` instead); remove the flag |
| 28 | `CertNotValid` | Certificate signature verified, but the check time falls outside its validity window |
| 29 | `CertUseNotPermitted` | Certificate does not authorize the requested use (encrypt or sign) |
| 30 | `TlockRoundNotReached` | Time-locked (v11) file's target drand round has not fired yet; try again later |
| 31 | `TlockBeaconFetchFailed` | Fetching the drand beacon failed for a reason other than "not yet reached" |
| 32 | `TlockDecryptionFailed` | Beacon signature was fetched but tlock/AEAD decryption failed; ciphertext is likely corrupt or tampered |
| 33 | `WebauthnPrfRequired` | v10 file was encrypted with a WebAuthn `prf` second factor; present the same enrolled passkey |
| 34 | `WebauthnPrfNotRequired` | A WebAuthn PRF output was supplied but the file was not encrypted with one (or uses a different second factor); remove it and retry |
| 35 | `SealedSenderAuthFailed` | Sealed-sender deniable-authentication tag did not verify against the claimed sender's identity key |
| 36 | `CertRevoked` | Certificate appears in a verified revocation list the caller chose to consult |
| 37 | `StegoCapacityExceeded` | `bury`'s cover image is too small to hold the payload; use a larger image |
| 38 | `StegoPayloadNotFound` | `exhume` found no valid embedded payload (wrong passphrase, wrong image, or it was edited/corrupted since burying - deliberately indistinguishable) |
| 39 | `StegoInvalidImage` | Cover or stego image could not be decoded/encoded (unsupported or corrupt format) |
| 40 | `ResumeSourceChanged` | `encrypt --resume`'s source file no longer matches the checkpoint's recorded hash; refuses rather than splicing two versions together |
| 41 | `ResumeCheckpointInvalid` | Resume checkpoint or the partial output it describes is unusable (corrupt, too short, or its last chunk fails to authenticate) |
| 42 | `FecSidecarInvalid` | `--fec` parity sidecar could not be read (missing, corrupt header, or wrong version) - not the same as an uncorrectable block, which isn't an error at all |
| 43 | `AuditLogInvalid` | Audit log is malformed, a record's signature does not verify, the hash chain does not link correctly, or (with `--expect-tip`) the log's final chain hash does not match |
