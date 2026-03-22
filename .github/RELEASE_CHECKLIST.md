# Release Checklist

- [ ] Update `pubspec.yaml` version and confirm it matches `native/Cargo.toml`.
- [ ] Update `CHANGELOG.md`.
- [ ] Confirm `README.md` matches the current implementation.
- [ ] If this is the first release, publish `1.0.0` manually with `dart pub publish` before enabling automated publishing on pub.dev.
- [ ] After the first manual publish, enable GitHub Actions publishing on pub.dev for `arcas0803/just_crypto` with tag pattern `v{{version}}`.
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