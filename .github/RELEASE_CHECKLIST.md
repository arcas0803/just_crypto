# Release Checklist

- [ ] Update `pubspec.yaml` version and confirm it matches `native/Cargo.toml`.
- [ ] Update `CHANGELOG.md`.
- [ ] Confirm `README.md` matches the current implementation.
- [ ] Run `dart pub get`.
- [ ] Run `dart analyze`.
- [ ] Run `dart test`.
- [ ] Run `dart run example/just_crypto_example.dart`.
- [ ] Run `dart pub publish --dry-run`.
- [ ] Run `cargo fmt --check` in `native/`.
- [ ] Run `cargo clippy --all-targets -- -D warnings` in `native/`.
- [ ] Run `cargo test` in `native/`.
- [ ] Confirm CI passed on macOS, Linux, and Windows.
- [ ] Confirm security reporting instructions are still valid.
- [ ] Tag and publish only after the full matrix is green.