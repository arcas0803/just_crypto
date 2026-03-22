## Unreleased

- Added a domain-oriented public API in [lib/src/just_crypto_base.dart](lib/src/just_crypto_base.dart) for AEAD, CBC interoperability, signatures, key agreement, KDF, hashes, and MACs while preserving the original generic API for compatibility.
- Added domain-specific key, nonce, IV, and MAC-key generators so new code can avoid the enum-driven compatibility helpers.
- Added typed wrappers for key material, nonces, IVs, salts, signatures, and shared secrets in [lib/src/types.dart](lib/src/types.dart).
- Added DartDoc documentation with professional usage examples across the public Dart API and marked the generic compatibility surface as deprecated for new code.
- Added constant-time byte comparison and isolate wrappers for hash, HMAC, and comparison operations.
- Added automatic native cleanup for streaming contexts through a native finalizer in [lib/src/just_crypto_base.dart](lib/src/just_crypto_base.dart).
- Hardened KDF and signature validation in Dart and extended the public error model with salt-size validation in [lib/src/errors.dart](lib/src/errors.dart).
- Added explicit zeroization of native buffers and sensitive temporary Rust copies in [native/src/helpers.rs](native/src/helpers.rs) and [native/src/algorithms.rs](native/src/algorithms.rs).
- Added native Rust unit tests for regression-sensitive crypto flows in [native/src/algorithms.rs](native/src/algorithms.rs).
- Added interoperability coverage against `package:cryptography` plus broader roundtrip, tamper, and chunk-boundary property tests in [test/just_crypto_test.dart](test/just_crypto_test.dart).
- Rewrote [README.md](README.md) to match the real V1 scope, public security posture, and package-facing documentation.
- Added repository governance files including [LICENSE](LICENSE), issue templates under [.github/ISSUE_TEMPLATE](.github/ISSUE_TEMPLATE), and a release checklist in [.github/RELEASE_CHECKLIST.md](.github/RELEASE_CHECKLIST.md).

## 1.0.0

- Added full package documentation in [README.md](README.md), including installation, API overview, native-assets notes, current limitations, and publishing guidance.
- Replaced the template example with a complete runnable sample in [example/just_crypto_example.dart](example/just_crypto_example.dart).
- Added a reproducible benchmark in [benchmark/benchmark.dart](benchmark/benchmark.dart) comparing `just_crypto` against pure Dart implementations from `package:cryptography/dart.dart`.
- Added GitHub Actions workflows for CI validation and pub.dev publication in [.github/workflows/ci.yml](.github/workflows/ci.yml) and [.github/workflows/publish.yml](.github/workflows/publish.yml).
- Declared direct package dependencies needed by Dart Hooks and benchmark tooling in [pubspec.yaml](pubspec.yaml).
- Switched FFI bindings to declarative `@Native` definitions in [lib/src/bindings.dart](lib/src/bindings.dart) so the package aligns with Dart Hooks code assets instead of manual library loading.
