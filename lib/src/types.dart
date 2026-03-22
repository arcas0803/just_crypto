import 'dart:typed_data';

import 'errors.dart';

Uint8List _copyExact(
  Uint8List value,
  int expectedLength,
  int errorCode,
  String message,
) {
  if (value.length != expectedLength) {
    throw JustCryptoException(errorCode, message);
  }
  return Uint8List.fromList(value);
}

Uint8List _copyMinimum(
  Uint8List value,
  int minimumLength,
  int errorCode,
  String message,
) {
  if (value.length < minimumLength) {
    throw JustCryptoException(errorCode, message);
  }
  return Uint8List.fromList(value);
}

/// Compatibility enum for the low-level generic API.
///
/// New code should prefer the domain-specific entry points instead of selecting
/// algorithms manually:
///
/// - [JustCrypto.aead]
/// - [JustCrypto.cbc]
/// - [JustCrypto.signatures]
/// - [JustCrypto.keyAgreement]
/// - [JustCrypto.kdf]
/// - [JustCrypto.hashes]
/// - [JustCrypto.macs]
enum JustCryptoAlgorithm {
  aes256Gcm,
  chacha20Poly1305,
  argon2id,
  ed25519,
  x25519,
  sha256,
  blake3,
  aes128Cbc,
  aes256Cbc,
  hmacSha256,
}

/// Raw key pair returned by the compatibility API.
///
/// Prefer [Ed25519KeyPair] and [X25519KeyPair] when using the recommended
/// domain-specific API.
class JustCryptoKeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;

  JustCryptoKeyPair({
    required Uint8List publicKey,
    required Uint8List privateKey,
  }) : publicKey = Uint8List.fromList(publicKey),
       privateKey = Uint8List.fromList(privateKey);
}

class JustCryptoSecretKey {
  final Uint8List bytes;

  /// Creates a 32-byte secret key for AES-256-GCM, AES-256-CBC, or
  /// ChaCha20-Poly1305.
  JustCryptoSecretKey.aes256(Uint8List value)
    : bytes = _copyExact(
        value,
        32,
        JustCryptoErrorCodes.invalidKeySize,
        'AES-256 requires a 32-byte key.',
      );

  /// Creates a 16-byte secret key for AES-128-CBC.
  JustCryptoSecretKey.aes128(Uint8List value)
    : bytes = _copyExact(
        value,
        16,
        JustCryptoErrorCodes.invalidKeySize,
        'AES-128 requires a 16-byte key.',
      );

  /// Creates a secret key for HMAC-SHA256.
  ///
  /// A 32-byte key is a sensible default for new deployments, while the minimum
  /// accepted size is 16 bytes.
  JustCryptoSecretKey.hmacSha256(Uint8List value)
    : bytes = _copyMinimum(
        value,
        16,
        JustCryptoErrorCodes.invalidKeySize,
        'HMAC-SHA256 requires a key with at least 16 bytes.',
      );
}

/// Typed Ed25519 private key.
class Ed25519PrivateKey {
  final Uint8List bytes;

  Ed25519PrivateKey(Uint8List value)
    : bytes = _copyExact(
        value,
        32,
        JustCryptoErrorCodes.invalidKeySize,
        'Ed25519 private keys must be 32 bytes.',
      );
}

/// Typed Ed25519 public key.
class Ed25519PublicKey {
  final Uint8List bytes;

  Ed25519PublicKey(Uint8List value)
    : bytes = _copyExact(
        value,
        32,
        JustCryptoErrorCodes.invalidKeySize,
        'Ed25519 public keys must be 32 bytes.',
      );
}

/// Typed X25519 private key.
class X25519PrivateKey {
  final Uint8List bytes;

  X25519PrivateKey(Uint8List value)
    : bytes = _copyExact(
        value,
        32,
        JustCryptoErrorCodes.invalidKeySize,
        'X25519 private keys must be 32 bytes.',
      );
}

/// Typed X25519 public key.
class X25519PublicKey {
  final Uint8List bytes;

  X25519PublicKey(Uint8List value)
    : bytes = _copyExact(
        value,
        32,
        JustCryptoErrorCodes.invalidKeySize,
        'X25519 public keys must be 32 bytes.',
      );
}

/// Ed25519 key pair returned by [JustCryptoSignatures.generateEd25519KeyPair].
class Ed25519KeyPair {
  final Ed25519PublicKey publicKey;
  final Ed25519PrivateKey privateKey;

  Ed25519KeyPair({required this.publicKey, required this.privateKey});
}

/// X25519 key pair returned by [JustCryptoKeyAgreement.generateX25519KeyPair].
class X25519KeyPair {
  final X25519PublicKey publicKey;
  final X25519PrivateKey privateKey;

  X25519KeyPair({required this.publicKey, required this.privateKey});
}

/// Typed 12-byte nonce for AEAD operations.
///
/// Example:
/// ```dart
/// final crypto = JustCrypto();
/// final nonce = crypto.aead.generateNonce();
/// ```
class JustCryptoNonce {
  final Uint8List value;

  JustCryptoNonce.aead(Uint8List value)
    : value = _copyExact(
        value,
        12,
        JustCryptoErrorCodes.invalidNonceSize,
        'AEAD algorithms require a 12-byte nonce.',
      );
}

/// Typed 16-byte IV for CBC interoperability operations.
class JustCryptoIv {
  final Uint8List value;

  JustCryptoIv.aesCbc(Uint8List value)
    : value = _copyExact(
        value,
        16,
        JustCryptoErrorCodes.invalidIvSize,
        'AES-CBC requires a 16-byte IV.',
      );
}

/// Typed salt for Argon2id derivation.
class JustCryptoSalt {
  final Uint8List value;

  JustCryptoSalt.argon2id(Uint8List value)
    : value = _copyMinimum(
        value,
        16,
        JustCryptoErrorCodes.invalidSaltSize,
        'Argon2id requires a salt with at least 16 bytes.',
      );
}

/// Typed Ed25519 signature.
class JustCryptoSignature {
  final Uint8List value;

  JustCryptoSignature.ed25519(Uint8List value)
    : value = _copyExact(
        value,
        64,
        JustCryptoErrorCodes.invalidSignature,
        'Ed25519 signatures must be 64 bytes.',
      );
}

/// Hash or MAC output returned by the high-level API.
class JustCryptoDigest {
  final Uint8List value;

  JustCryptoDigest(Uint8List value) : value = Uint8List.fromList(value);
}

/// Typed X25519 shared secret.
class JustCryptoSharedSecret {
  final Uint8List value;

  JustCryptoSharedSecret(Uint8List value)
    : value = _copyExact(
        value,
        32,
        JustCryptoErrorCodes.invalidKeySize,
        'X25519 shared secrets must be 32 bytes.',
      );
}
