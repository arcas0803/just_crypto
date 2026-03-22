# just_crypto

just_crypto is a Dart package backed by a Rust native library through Dart native assets. It provides a Dart-first API with explicit cryptographic domains, typed key material, isolate helpers, and a native backend focused on a small, explicit cryptographic surface.

## Positioning

- Recommended for: projects that want a Dart API with a Rust cryptography backend and explicit control over supported primitives.
- Not yet recommended as a post-audit cryptography dependency: the project is still pre-audit.
- Scope of V1: AEAD, CBC interoperability, Ed25519, X25519, Argon2id, SHA-256, BLAKE3, HMAC-SHA256, and streaming for hash/HMAC only.

## Supported primitives

| Domain | Primitive | Status | Recommended | Notes |
| --- | --- | --- | --- | --- |
| AEAD | AES-256-GCM | Stable | Yes | Recommended default for new encryption flows |
| AEAD | ChaCha20-Poly1305 | Stable | Yes | Recommended alternative to AES-GCM |
| CBC | AES-128-CBC | Compatibility | Only for interop | No built-in authentication |
| CBC | AES-256-CBC | Compatibility | Only for interop | No built-in authentication |
| Signatures | Ed25519 | Stable | Yes | Signing, verification, key generation |
| Key agreement | X25519 | Stable | Yes | Key generation and shared-secret derivation |
| KDF | Argon2id | Stable | Yes | Salt must be at least 16 bytes |
| Hash | SHA-256 | Stable | Yes | One-shot and streaming |
| Hash | BLAKE3 | Stable | Yes | One-shot and streaming |
| MAC | HMAC-SHA256 | Stable | Yes | One-shot and streaming |

Legacy algorithms such as SHA-1, MD5, and HMAC-SHA1 are intentionally excluded from the professional public API.

## Requirements

- Dart 3.11 or newer
- Rust 1.89.0 available through rustup
- cargo available in PATH

The package relies on Dart native assets, so the native library is built automatically during normal Dart workflows such as `dart run`, `dart test`, and `dart pub publish --dry-run`.

## Installation

```bash
dart pub add just_crypto
rustup toolchain install 1.89.0
```

The Rust toolchain is pinned in [native/rust-toolchain.toml](native/rust-toolchain.toml).

## Recommended API

The package still exposes the original generic `JustCrypto` methods for compatibility, but new code should prefer the domain-oriented API.

### AEAD

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:just_crypto/just_crypto.dart';

Future<void> main() async {
  final crypto = JustCrypto();
  final key = crypto.aead.generateAes256GcmKey();
  final nonce = crypto.aead.generateNonce();
  final message = Uint8List.fromList(utf8.encode('hello just_crypto'));
  final aad = Uint8List.fromList(utf8.encode('metadata'));

  final ciphertext = crypto.aead.encryptAes256Gcm(
    message: message,
    key: key,
    nonce: nonce,
    aad: aad,
  );

  final plaintext = crypto.aead.decryptAes256Gcm(
    message: ciphertext,
    key: key,
    nonce: nonce,
    aad: aad,
  );

  print(utf8.decode(plaintext));
}
```

### Signatures

```dart
final crypto = JustCrypto();
final pair = crypto.signatures.generateEd25519KeyPair();
final message = Uint8List.fromList('sign me'.codeUnits);

final signature = crypto.signatures.signEd25519(
  message: message,
  privateKey: pair.privateKey,
);

final verified = crypto.signatures.verifyEd25519(
  message: message,
  signature: signature,
  publicKey: pair.publicKey,
);
```

### Key agreement

```dart
final crypto = JustCrypto();
final alice = crypto.keyAgreement.generateX25519KeyPair();
final bob = crypto.keyAgreement.generateX25519KeyPair();

final aliceSecret = crypto.keyAgreement.deriveSharedSecretX25519(
  privateKey: alice.privateKey,
  publicKey: bob.publicKey,
);
```

### KDF, hash, and MAC

```dart
final crypto = JustCrypto();
final salt = crypto.kdf.generateArgon2idSalt();
final derived = crypto.kdf.deriveArgon2id(
  input: Uint8List.fromList('password'.codeUnits),
  salt: salt,
);

final sha256 = crypto.hashes.sha256(Uint8List.fromList('abc'.codeUnits));
final hmac = crypto.macs.hmacSha256(
  message: Uint8List.fromList('abc'.codeUnits),
  key: crypto.macs.generateHmacSha256Key(),
);
```

## Compatibility API

The generic methods below remain available for compatibility and advanced use cases, but they are now explicitly deprecated in the Dart API to steer new code toward the typed domain surface:

- `encryptMessage`
- `decryptMessage`
- `signMessage`
- `verifyMessage`
- `deriveKey`
- `generateKeyPair`
- `deriveSharedSecret`
- `hashMessage`
- `hmacMessage`

New code should prefer the domain-specific API exposed through:

- `aead`
- `cbc`
- `signatures`
- `keyAgreement`
- `kdf`
- `hashes`
- `macs`

## Typed materials and sizes

| Type | Length |
| --- | --- |
| AES-256 / ChaCha20 key | 32 bytes |
| AES-128 key | 16 bytes |
| AEAD nonce | 12 bytes |
| CBC IV | 16 bytes |
| Ed25519 private key | 32 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |
| X25519 private key | 32 bytes |
| X25519 public key | 32 bytes |
| X25519 shared secret | 32 bytes |
| Argon2id salt | 16 bytes minimum |
| SHA-256 digest | 32 bytes |
| BLAKE3 digest | 32 bytes |
| HMAC-SHA256 tag | 32 bytes |

## Streaming support

Supported:

- SHA-256
- BLAKE3
- HMAC-SHA256

Not supported in V1:

- stateful encryption
- stateful decryption

Streaming contexts now use a native finalizer as a safety net, but `dispose()` is still the preferred deterministic cleanup path.

## Constant-time comparison

Use:

- `crypto.constantTimeEquals(...)`
- `crypto.macs.constantTimeEquals(...)`

This helper is intended for comparing MACs, digests, secrets, and other sensitive byte sequences without relying on ad hoc equality code.

## Isolates

The package exposes isolate wrappers for:

- encryption and decryption
- signing and verification
- key derivation
- key generation
- shared-secret derivation
- one-shot hashing
- one-shot HMAC
- constant-time equality checks

The isolate variants include scheduling overhead. Prefer synchronous calls for small, latency-sensitive operations.

## Error model

Native errors are mapped to `JustCryptoException` with stable numeric codes. Common cases include:

- invalid key size
- invalid nonce size
- invalid IV size
- invalid salt size
- invalid signature
- invalid pointer/length pair
- invalid native state
- unsupported algorithm for the requested operation

See [lib/src/errors.dart](lib/src/errors.dart) for the canonical mapping.

## Security posture

- Prefer `aead.encryptAes256Gcm` or `aead.encryptChaCha20Poly1305` for new encryption flows.
- Treat CBC as compatibility-only.
- Use unique nonces and IVs for each encryption call.
- Prefer typed wrappers for keys, nonces, IVs, signatures, and shared secrets.
- Prefer the domain generators such as `aead.generateNonce`, `cbc.generateIv`, and `macs.generateHmacSha256Key` over raw byte plumbing in application code.
- The package now zeroizes native buffers it owns and wipes temporary FFI copies before release.
- The project is still pre-audit and should be treated accordingly.

## Current limitations

- The package is pre-audit and has not completed an external cryptographic review.
- Stateful encryption/decryption streaming is not implemented.
- Repository metadata fields such as `repository`, `homepage`, and `issue_tracker` still need final real values before public distribution if this workspace is published outside a local environment.

## Security

### Supported surface

The public security surface of the package is intentionally limited to the primitives documented as in-scope:

- AES-256-GCM
- ChaCha20-Poly1305
- AES-128-CBC and AES-256-CBC for interoperability scenarios
- Ed25519
- X25519 key agreement
- Argon2id
- SHA-256
- BLAKE3
- HMAC-SHA256

Legacy algorithms such as SHA-1, MD5, and HMAC-SHA1 are intentionally excluded from the supported public surface.

### Security expectations

- Prefer AEAD modes over CBC for new designs.
- Treat CBC as interoperability support, not as the default recommendation.
- Use unique nonces and IVs for every encryption operation.
- Prefer the domain-specific API surface over the deprecated generic enum-driven API when writing new code.
- Keep private keys and shared secrets outside logs, crash reports, and analytics payloads.
- Review platform key storage and application threat models separately from this library.

### Reporting a vulnerability

If you identify a security issue, do not open a public issue with exploit details.

Report the issue privately to the maintainers and include:

- affected version
- platform and architecture
- minimal reproduction
- impact assessment
- any proof-of-concept code or traces needed to reproduce the issue

Current workspace status:

- no repository-backed private reporting endpoint is configured yet.
- no public vulnerability issue flow should be considered valid for sensitive reports.

Until a dedicated private reporting channel is configured in repository metadata or release operations, keep vulnerability discussions private.

## Local use

Typical local workflow:

```bash
dart pub get
dart analyze
dart test
dart run example/just_crypto_example.dart
```

Optional benchmark:

```bash
dart run benchmark/benchmark.dart
```

For a runnable end-to-end sample, see [example/just_crypto_example.dart](example/just_crypto_example.dart).