/// Dart-first cryptography package backed by a Rust native implementation.
///
/// New code should prefer the domain-oriented API exposed by [JustCrypto]:
///
/// - [JustCrypto.aead] for authenticated encryption
/// - [JustCrypto.cbc] for CBC interoperability only
/// - [JustCrypto.signatures] for Ed25519
/// - [JustCrypto.keyAgreement] for X25519
/// - [JustCrypto.kdf] for Argon2id
/// - [JustCrypto.hashes] for SHA-256 and BLAKE3
/// - [JustCrypto.macs] for HMAC-SHA256 and constant-time comparison
///
/// Example:
/// ```
/// import 'dart:convert';
/// import 'dart:typed_data';
///
/// import 'package:just_crypto/just_crypto.dart';
///
/// void main() {
///   final crypto = JustCrypto();
///   final key = crypto.aead.generateAes256GcmKey();
///   final nonce = crypto.aead.generateNonce();
///   final message = Uint8List.fromList(utf8.encode('hello just_crypto'));
///
///   final ciphertext = crypto.aead.encryptAes256Gcm(
///     message: message,
///     key: key,
///     nonce: nonce,
///   );
///
///   final plaintext = crypto.aead.decryptAes256Gcm(
///     message: ciphertext,
///     key: key,
///     nonce: nonce,
///   );
///
///   print(utf8.decode(plaintext));
/// }
/// ```
library;

export 'src/errors.dart';
export 'src/just_crypto_base.dart';
export 'src/types.dart';
