## Unreleased

## 1.0.1

- Added `x86_64-unknown-linux-gnu` to [native/rust-toolchain.toml](native/rust-toolchain.toml) so Linux GitHub Actions runners can build native assets during publish validation.
- Applied canonical Rust formatting across native sources so `cargo fmt --check` no longer fails in CI or publish jobs.
- Bumped the package version in [pubspec.yaml](pubspec.yaml) and [native/Cargo.toml](native/Cargo.toml) to keep release metadata aligned.

## 1.0.0

- Added full package documentation in [README.md](README.md), including installation, API overview, native-assets notes, current limitations, and publishing guidance.
- Replaced the template example with a complete runnable sample in [example/just_crypto_example.dart](example/just_crypto_example.dart).
- Added a reproducible benchmark in [benchmark/benchmark.dart](benchmark/benchmark.dart) comparing `just_crypto` against pure Dart implementations from `package:cryptography/dart.dart`.
- Added GitHub Actions workflows for CI validation and pub.dev publication in [.github/workflows/ci.yml](.github/workflows/ci.yml) and [.github/workflows/publish.yml](.github/workflows/publish.yml).
- Declared direct package dependencies needed by Dart Hooks and benchmark tooling in [pubspec.yaml](pubspec.yaml).
- Switched FFI bindings to declarative `@Native` definitions in [lib/src/bindings.dart](lib/src/bindings.dart) so the package aligns with Dart Hooks code assets instead of manual library loading.
