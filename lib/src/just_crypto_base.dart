import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'bindings.dart';
import 'errors.dart';
import 'helpers.dart';
import 'types.dart';

final ffi.NativeFinalizer _streamContextFinalizer = ffi.NativeFinalizer(
  ffi.Native.addressOf(jcStreamFree),
);

/// Main entry point for the just_crypto Dart API.
///
/// Prefer the domain-oriented properties over the compatibility methods. The
/// compatibility surface remains available for migration scenarios, but new code
/// should use typed wrappers and domain-specific methods.
///
/// Example:
/// ```dart
/// import 'dart:convert';
/// import 'dart:typed_data';
///
/// import 'package:just_crypto/just_crypto.dart';
///
/// void main() {
///   final crypto = JustCrypto();
///   final key = crypto.aead.generateAes256GcmKey();
///   final nonce = crypto.aead.generateNonce();
///   final message = Uint8List.fromList(utf8.encode('hello'));
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
class JustCrypto {
  /// Authenticated encryption entry points for AES-256-GCM and
  /// ChaCha20-Poly1305.
  late final JustCryptoAead aead = JustCryptoAead._(this);

  /// CBC interoperability helpers.
  late final JustCryptoCbcCompatibility cbc = JustCryptoCbcCompatibility._(
    this,
  );

  /// Ed25519 key generation, signing, and verification.
  late final JustCryptoSignatures signatures = JustCryptoSignatures._(this);

  /// X25519 key generation and shared-secret derivation.
  late final JustCryptoKeyAgreement keyAgreement = JustCryptoKeyAgreement._(
    this,
  );

  /// Argon2id derivation helpers.
  late final JustCryptoKdf kdf = JustCryptoKdf._(this);

  /// SHA-256 and BLAKE3 helpers.
  late final JustCryptoHashes hashes = JustCryptoHashes._(this);

  /// HMAC-SHA256 and constant-time comparison helpers.
  late final JustCryptoMacs macs = JustCryptoMacs._(this);

  /// Compatibility wrapper for algorithm-driven encryption.
  ///
  /// Prefer [aead] or [cbc] in new code.
  @Deprecated('Use JustCrypto.aead or JustCrypto.cbc instead.')
  Uint8List encryptMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
    Uint8List? aad,
  }) {
    return _encryptMessage(
      algorithm: algorithm,
      message: message,
      key: key,
      nonce: nonce,
      iv: iv,
      aad: aad,
    );
  }

  Uint8List _encryptMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
    Uint8List? aad,
  }) {
    _validateCipherParams(algorithm: algorithm, key: key, nonce: nonce, iv: iv);

    final effectiveNonce = nonce ?? iv;

    return withPointer(message, (msgPtr, msgLen) {
      return withPointer(key, (keyPtr, keyLen) {
        return withPointer(effectiveNonce, (noncePtr, nonceLen) {
          return withPointer(aad, (aadPtr, aadLen) {
            final result = jcEncrypt(
              algorithm.index,
              msgPtr,
              msgLen,
              keyPtr,
              keyLen,
              noncePtr,
              nonceLen,
              aadPtr,
              aadLen,
            );
            return parseAndFreeResult(result);
          });
        });
      });
    });
  }

  /// Compatibility wrapper for algorithm-driven decryption.
  ///
  /// Prefer [aead] or [cbc] in new code.
  @Deprecated('Use JustCrypto.aead or JustCrypto.cbc instead.')
  Uint8List decryptMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
    Uint8List? aad,
  }) {
    return _decryptMessage(
      algorithm: algorithm,
      message: message,
      key: key,
      nonce: nonce,
      iv: iv,
      aad: aad,
    );
  }

  Uint8List _decryptMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
    Uint8List? aad,
  }) {
    _validateCipherParams(algorithm: algorithm, key: key, nonce: nonce, iv: iv);

    final effectiveNonce = nonce ?? iv;

    return withPointer(message, (msgPtr, msgLen) {
      return withPointer(key, (keyPtr, keyLen) {
        return withPointer(effectiveNonce, (noncePtr, nonceLen) {
          return withPointer(aad, (aadPtr, aadLen) {
            final result = jcDecrypt(
              algorithm.index,
              msgPtr,
              msgLen,
              keyPtr,
              keyLen,
              noncePtr,
              nonceLen,
              aadPtr,
              aadLen,
            );
            return parseAndFreeResult(result);
          });
        });
      });
    });
  }

  /// Compatibility wrapper for algorithm-driven signing.
  ///
  /// Prefer [signatures] in new code.
  @Deprecated('Use JustCrypto.signatures instead.')
  Uint8List signMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List privateKey,
  }) {
    return _signMessage(
      algorithm: algorithm,
      message: message,
      privateKey: privateKey,
    );
  }

  Uint8List _signMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List privateKey,
  }) {
    _validateSignatureAlgorithm(algorithm);
    _validatePrivateKeySize(algorithm, privateKey);

    return withPointer(message, (msgPtr, msgLen) {
      return withPointer(privateKey, (privKeyPtr, privKeyLen) {
        final result = jcSign(
          algorithm.index,
          msgPtr,
          msgLen,
          privKeyPtr,
          privKeyLen,
        );
        return parseAndFreeResult(result);
      });
    });
  }

  /// Compatibility wrapper for algorithm-driven verification.
  ///
  /// Prefer [signatures] in new code.
  @Deprecated('Use JustCrypto.signatures instead.')
  bool verifyMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  }) {
    return _verifyMessage(
      algorithm: algorithm,
      message: message,
      signature: signature,
      publicKey: publicKey,
    );
  }

  bool _verifyMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  }) {
    _validateSignatureAlgorithm(algorithm);
    _validatePublicKeySize(algorithm, publicKey);

    return withPointer(message, (msgPtr, msgLen) {
      return withPointer(signature, (sigPtr, sigLen) {
        return withPointer(publicKey, (pubKeyPtr, pubKeyLen) {
          final code = jcVerify(
            algorithm.index,
            msgPtr,
            msgLen,
            sigPtr,
            sigLen,
            pubKeyPtr,
            pubKeyLen,
          );
          if (code == 0) return true;
          if (code == -7) return false; // JC_ERR_INVALID_SIGNATURE
          throwOnFailure(code);
          return false; // Not reachable but needed for compile
        });
      });
    });
  }

  /// Compatibility wrapper for algorithm-driven key derivation.
  ///
  /// Prefer [kdf] in new code.
  @Deprecated('Use JustCrypto.kdf instead.')
  Uint8List deriveKey({
    required JustCryptoAlgorithm algorithm,
    required Uint8List input,
    Uint8List? salt,
    int? memoryCost,
    int? timeCost,
    int? parallelism,
    int? outputLength,
  }) {
    return _deriveKey(
      algorithm: algorithm,
      input: input,
      salt: salt,
      memoryCost: memoryCost,
      timeCost: timeCost,
      parallelism: parallelism,
      outputLength: outputLength,
    );
  }

  Uint8List _deriveKey({
    required JustCryptoAlgorithm algorithm,
    required Uint8List input,
    Uint8List? salt,
    int? memoryCost,
    int? timeCost,
    int? parallelism,
    int? outputLength,
  }) {
    _validateKdfAlgorithm(algorithm);
    _validateKdfParams(salt: salt, outputLength: outputLength);

    return withPointer(input, (inputPtr, inputLen) {
      return withPointer(salt, (saltPtr, saltLen) {
        final result = jcDeriveKey(
          algorithm.index,
          inputPtr,
          inputLen,
          saltPtr,
          saltLen,
          memoryCost ?? 0,
          timeCost ?? 0,
          parallelism ?? 0,
          outputLength ?? 0,
        );
        return parseAndFreeResult(result);
      });
    });
  }

  /// Compatibility wrapper for algorithm-driven key-pair generation.
  ///
  /// Prefer [signatures.generateEd25519KeyPair] or
  /// [keyAgreement.generateX25519KeyPair] in new code.
  @Deprecated('Use JustCrypto.signatures or JustCrypto.keyAgreement instead.')
  JustCryptoKeyPair generateKeyPair({required JustCryptoAlgorithm algorithm}) {
    return _generateKeyPair(algorithm: algorithm);
  }

  JustCryptoKeyPair _generateKeyPair({required JustCryptoAlgorithm algorithm}) {
    _validateKeyPairAlgorithm(algorithm);
    final result = jcGenerateKeyPair(algorithm.index);
    final bytes = parseAndFreeResult(result);
    // bytes should be 64 bytes total for Ed25519 and X25519
    if (bytes.length == 64) {
      return JustCryptoKeyPair(
        privateKey: Uint8List.fromList(bytes.sublist(0, 32)),
        publicKey: Uint8List.fromList(bytes.sublist(32, 64)),
      );
    }
    throw JustCryptoException(
      -1,
      'Invalid key pair length returned from native: ${bytes.length}',
    );
  }

  /// Compatibility wrapper for raw nonce generation.
  ///
  /// Prefer [JustCryptoAead.generateNonce] in new code.
  @Deprecated('Use JustCrypto.aead.generateNonce instead.')
  Uint8List generateNonce({required JustCryptoAlgorithm algorithm}) {
    return _generateNonceBytesForAlgorithm(algorithm: algorithm);
  }

  Uint8List _generateNonceBytesForAlgorithm({
    required JustCryptoAlgorithm algorithm,
  }) {
    switch (algorithm) {
      case JustCryptoAlgorithm.aes256Gcm:
      case JustCryptoAlgorithm.chacha20Poly1305:
        return _generateRandom(12);
      default:
        throw const JustCryptoException(
          JustCryptoErrorCodes.unsupportedAlgo,
          'Nonce generation is only available for AEAD algorithms.',
        );
    }
  }

  /// Compatibility wrapper for raw IV generation.
  ///
  /// Prefer [JustCryptoCbcCompatibility.generateIv] in new code.
  @Deprecated('Use JustCrypto.cbc.generateIv instead.')
  Uint8List generateIv({required JustCryptoAlgorithm algorithm}) {
    return _generateIvBytesForAlgorithm(algorithm: algorithm);
  }

  Uint8List _generateIvBytesForAlgorithm({
    required JustCryptoAlgorithm algorithm,
  }) {
    switch (algorithm) {
      case JustCryptoAlgorithm.aes128Cbc:
      case JustCryptoAlgorithm.aes256Cbc:
        return _generateRandom(16);
      default:
        throw const JustCryptoException(
          JustCryptoErrorCodes.unsupportedAlgo,
          'IV generation is only available for CBC algorithms.',
        );
    }
  }

  /// Compatibility wrapper for raw salt generation.
  ///
  /// Prefer [JustCryptoKdf.generateArgon2idSalt] in new code.
  @Deprecated('Use JustCrypto.kdf.generateArgon2idSalt instead.')
  Uint8List generateSalt({required JustCryptoAlgorithm algorithm}) {
    return _generateSaltBytesForAlgorithm(algorithm: algorithm);
  }

  Uint8List _generateSaltBytesForAlgorithm({
    required JustCryptoAlgorithm algorithm,
  }) {
    _validateKdfAlgorithm(algorithm);
    return _generateRandom(16);
  }

  Uint8List _generateRandom(int length) {
    final result = jcGenerateRandom(length);
    return parseAndFreeResult(result);
  }

  /// Compatibility wrapper for algorithm-driven hashing.
  ///
  /// Prefer [hashes] in new code.
  @Deprecated('Use JustCrypto.hashes instead.')
  Uint8List hashMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
  }) {
    return _hashMessage(algorithm: algorithm, message: message);
  }

  Uint8List _hashMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
  }) {
    _validateHashAlgorithm(algorithm);
    return withPointer(message, (msgPtr, msgLen) {
      final result = jcHashMessage(algorithm.index, msgPtr, msgLen);
      return parseAndFreeResult(result);
    });
  }

  /// Compatibility wrapper for algorithm-driven MAC generation.
  ///
  /// Prefer [macs] in new code.
  @Deprecated('Use JustCrypto.macs instead.')
  Uint8List hmacMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
  }) {
    return _hmacMessage(algorithm: algorithm, message: message, key: key);
  }

  Uint8List _hmacMessage({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
  }) {
    _validateHmacAlgorithm(algorithm);
    return withPointer(message, (msgPtr, msgLen) {
      return withPointer(key, (keyPtr, keyLen) {
        final result = jcHmacMessage(
          algorithm.index,
          msgPtr,
          msgLen,
          keyPtr,
          keyLen,
        );
        return parseAndFreeResult(result);
      });
    });
  }

  /// Compatibility wrapper for algorithm-driven shared-secret derivation.
  ///
  /// Prefer [keyAgreement] in new code.
  @Deprecated('Use JustCrypto.keyAgreement instead.')
  Uint8List deriveSharedSecret({
    required JustCryptoAlgorithm algorithm,
    required Uint8List privateKey,
    required Uint8List publicKey,
  }) {
    return _deriveSharedSecret(
      algorithm: algorithm,
      privateKey: privateKey,
      publicKey: publicKey,
    );
  }

  Uint8List _deriveSharedSecret({
    required JustCryptoAlgorithm algorithm,
    required Uint8List privateKey,
    required Uint8List publicKey,
  }) {
    if (algorithm != JustCryptoAlgorithm.x25519) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.unsupportedAlgo,
        'Shared-secret derivation is only supported for X25519.',
      );
    }

    if (privateKey.length != 32 || publicKey.length != 32) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.invalidKeySize,
        'X25519 shared-secret derivation requires 32-byte keys.',
      );
    }

    return withPointer(privateKey, (privateKeyPtr, privateKeyLen) {
      return withPointer(publicKey, (publicKeyPtr, publicKeyLen) {
        final result = jcSharedSecret(
          algorithm.index,
          privateKeyPtr,
          privateKeyLen,
          publicKeyPtr,
          publicKeyLen,
        );
        return parseAndFreeResult(result);
      });
    });
  }

  /// Compatibility isolate wrapper for [encryptMessage].
  @Deprecated('Use the isolate helpers in JustCrypto.aead or JustCrypto.cbc.')
  Future<Uint8List> encryptMessageIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
    Uint8List? aad,
  }) {
    return Isolate.run(
      () => _encryptMessage(
        algorithm: algorithm,
        message: message,
        key: key,
        nonce: nonce,
        iv: iv,
        aad: aad,
      ),
    );
  }

  /// Compatibility isolate wrapper for [decryptMessage].
  @Deprecated('Use the isolate helpers in JustCrypto.aead or JustCrypto.cbc.')
  Future<Uint8List> decryptMessageIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
    Uint8List? aad,
  }) {
    return Isolate.run(
      () => _decryptMessage(
        algorithm: algorithm,
        message: message,
        key: key,
        nonce: nonce,
        iv: iv,
        aad: aad,
      ),
    );
  }

  /// Compatibility isolate wrapper for [signMessage].
  @Deprecated('Use the isolate helpers in JustCrypto.signatures.')
  Future<Uint8List> signMessageIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List privateKey,
  }) {
    return Isolate.run(
      () => _signMessage(
        algorithm: algorithm,
        message: message,
        privateKey: privateKey,
      ),
    );
  }

  /// Compatibility isolate wrapper for [verifyMessage].
  @Deprecated('Use the isolate helpers in JustCrypto.signatures.')
  Future<bool> verifyMessageIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  }) {
    return Isolate.run(
      () => _verifyMessage(
        algorithm: algorithm,
        message: message,
        signature: signature,
        publicKey: publicKey,
      ),
    );
  }

  /// Compatibility isolate wrapper for [deriveKey].
  @Deprecated('Use the isolate helpers in JustCrypto.kdf.')
  Future<Uint8List> deriveKeyIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List input,
    Uint8List? salt,
    int? memoryCost,
    int? timeCost,
    int? parallelism,
    int? outputLength,
  }) {
    return Isolate.run(
      () => _deriveKey(
        algorithm: algorithm,
        input: input,
        salt: salt,
        memoryCost: memoryCost,
        timeCost: timeCost,
        parallelism: parallelism,
        outputLength: outputLength,
      ),
    );
  }

  /// Compatibility isolate wrapper for [generateKeyPair].
  @Deprecated(
    'Use the isolate helpers in JustCrypto.signatures or keyAgreement.',
  )
  Future<JustCryptoKeyPair> generateKeyPairIsolate({
    required JustCryptoAlgorithm algorithm,
  }) {
    return Isolate.run(() => _generateKeyPair(algorithm: algorithm));
  }

  /// Compatibility isolate wrapper for [deriveSharedSecret].
  @Deprecated('Use the isolate helpers in JustCrypto.keyAgreement.')
  Future<Uint8List> deriveSharedSecretIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List privateKey,
    required Uint8List publicKey,
  }) {
    return Isolate.run(
      () => _deriveSharedSecret(
        algorithm: algorithm,
        privateKey: privateKey,
        publicKey: publicKey,
      ),
    );
  }

  /// Compatibility isolate wrapper for [hashMessage].
  @Deprecated('Use the isolate helpers in JustCrypto.hashes.')
  Future<Uint8List> hashMessageIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
  }) {
    return Isolate.run(
      () => _hashMessage(algorithm: algorithm, message: message),
    );
  }

  /// Compatibility isolate wrapper for [hmacMessage].
  @Deprecated('Use the isolate helpers in JustCrypto.macs.')
  Future<Uint8List> hmacMessageIsolate({
    required JustCryptoAlgorithm algorithm,
    required Uint8List message,
    required Uint8List key,
  }) {
    return Isolate.run(
      () => _hmacMessage(algorithm: algorithm, message: message, key: key),
    );
  }

  bool constantTimeEquals({required Uint8List left, required Uint8List right}) {
    return withPointer(left, (leftPtr, leftLen) {
      return withPointer(right, (rightPtr, rightLen) {
        final code = jcConstantTimeEq(leftPtr, leftLen, rightPtr, rightLen);
        if (code == 1) return true;
        if (code == 0) return false;
        throwOnFailure(code);
        return false;
      });
    });
  }

  Future<bool> constantTimeEqualsIsolate({
    required Uint8List left,
    required Uint8List right,
  }) {
    return Isolate.run(() => constantTimeEquals(left: left, right: right));
  }

  /// Compatibility wrapper for algorithm-driven streaming hash contexts.
  ///
  /// Prefer [JustCryptoHashes.createSha256Context] or
  /// [JustCryptoHashes.createBlake3Context] in new code.
  @Deprecated(
    'Use JustCrypto.hashes.createSha256Context or createBlake3Context.',
  )
  JustCryptoHashContext createHashContext({
    required JustCryptoAlgorithm algorithm,
  }) {
    return _createHashContext(algorithm: algorithm);
  }

  JustCryptoHashContext _createHashContext({
    required JustCryptoAlgorithm algorithm,
  }) {
    _validateHashAlgorithm(algorithm);
    final ctxPtr = jcStreamInitHash(algorithm.index);
    if (ctxPtr.address == 0) {
      throw const JustCryptoException(-1, 'Failed to initialize hash context');
    }
    return JustCryptoHashContext._(ctxPtr);
  }

  /// Compatibility wrapper for algorithm-driven streaming HMAC contexts.
  ///
  /// Prefer [JustCryptoMacs.createHmacSha256Context] in new code.
  @Deprecated('Use JustCrypto.macs.createHmacSha256Context instead.')
  JustCryptoHashContext createHmacContext({
    required JustCryptoAlgorithm algorithm,
    required Uint8List key,
  }) {
    return _createHmacContext(algorithm: algorithm, key: key);
  }

  JustCryptoHashContext _createHmacContext({
    required JustCryptoAlgorithm algorithm,
    required Uint8List key,
  }) {
    _validateHmacAlgorithm(algorithm);
    return withPointer(key, (keyPtr, keyLen) {
      final ctxPtr = jcStreamInitHmac(algorithm.index, keyPtr, keyLen);
      if (ctxPtr.address == 0) {
        throw const JustCryptoException(
          -1,
          'Failed to initialize HMAC context',
        );
      }
      return JustCryptoHashContext._(ctxPtr);
    });
  }

  void _validateCipherParams({
    required JustCryptoAlgorithm algorithm,
    required Uint8List key,
    Uint8List? nonce,
    Uint8List? iv,
  }) {
    switch (algorithm) {
      case JustCryptoAlgorithm.aes256Gcm:
      case JustCryptoAlgorithm.chacha20Poly1305:
        if (key.length != 32) {
          throw const JustCryptoException(
            JustCryptoErrorCodes.invalidKeySize,
            'AEAD algorithms require a 32-byte key.',
          );
        }
        if (nonce == null || nonce.length != 12) {
          throw const JustCryptoException(
            JustCryptoErrorCodes.invalidNonceSize,
            'AEAD algorithms require a 12-byte nonce.',
          );
        }
      case JustCryptoAlgorithm.aes128Cbc:
        if (key.length != 16) {
          throw const JustCryptoException(
            JustCryptoErrorCodes.invalidKeySize,
            'AES-128-CBC requires a 16-byte key.',
          );
        }
        if (iv == null || iv.length != 16) {
          throw const JustCryptoException(
            JustCryptoErrorCodes.invalidIvSize,
            'AES-CBC requires a 16-byte IV.',
          );
        }
      case JustCryptoAlgorithm.aes256Cbc:
        if (key.length != 32) {
          throw const JustCryptoException(
            JustCryptoErrorCodes.invalidKeySize,
            'AES-256-CBC requires a 32-byte key.',
          );
        }
        if (iv == null || iv.length != 16) {
          throw const JustCryptoException(
            JustCryptoErrorCodes.invalidIvSize,
            'AES-CBC requires a 16-byte IV.',
          );
        }
      default:
        throw const JustCryptoException(
          JustCryptoErrorCodes.unsupportedAlgo,
          'Algorithm does not support encryption/decryption.',
        );
    }
  }

  void _validateHashAlgorithm(JustCryptoAlgorithm algorithm) {
    switch (algorithm) {
      case JustCryptoAlgorithm.sha256:
      case JustCryptoAlgorithm.blake3:
        return;
      default:
        throw const JustCryptoException(
          JustCryptoErrorCodes.unsupportedAlgo,
          'Algorithm does not support hashing.',
        );
    }
  }

  void _validateHmacAlgorithm(JustCryptoAlgorithm algorithm) {
    if (algorithm != JustCryptoAlgorithm.hmacSha256) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.unsupportedAlgo,
        'Algorithm does not support HMAC.',
      );
    }
  }

  void _validateKeyPairAlgorithm(JustCryptoAlgorithm algorithm) {
    switch (algorithm) {
      case JustCryptoAlgorithm.ed25519:
      case JustCryptoAlgorithm.x25519:
        return;
      default:
        throw const JustCryptoException(
          JustCryptoErrorCodes.unsupportedAlgo,
          'Key pair generation is only supported for Ed25519 and X25519.',
        );
    }
  }

  void _validateSignatureAlgorithm(JustCryptoAlgorithm algorithm) {
    if (algorithm != JustCryptoAlgorithm.ed25519) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.unsupportedAlgo,
        'This operation only supports Ed25519 signatures.',
      );
    }
  }

  void _validatePrivateKeySize(
    JustCryptoAlgorithm algorithm,
    Uint8List privateKey,
  ) {
    if (algorithm == JustCryptoAlgorithm.ed25519 && privateKey.length != 32) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.invalidKeySize,
        'Ed25519 private keys must be 32 bytes.',
      );
    }
  }

  void _validatePublicKeySize(
    JustCryptoAlgorithm algorithm,
    Uint8List publicKey,
  ) {
    if (algorithm == JustCryptoAlgorithm.ed25519 && publicKey.length != 32) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.invalidKeySize,
        'Ed25519 public keys must be 32 bytes.',
      );
    }
  }

  void _validateKdfAlgorithm(JustCryptoAlgorithm algorithm) {
    if (algorithm != JustCryptoAlgorithm.argon2id) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.unsupportedAlgo,
        'This operation only supports Argon2id.',
      );
    }
  }

  void _validateKdfParams({Uint8List? salt, int? outputLength}) {
    if (salt != null && salt.length < 16) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.invalidSaltSize,
        'Argon2id requires a salt with at least 16 bytes.',
      );
    }
    if (outputLength != null && outputLength <= 0) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.invalidParam,
        'The requested output length must be greater than zero.',
      );
    }
  }
}

/// Wraps a native streaming context and guarantees cleanup even if dispose is omitted.
class JustCryptoHashContext implements ffi.Finalizable {
  ffi.Pointer<ffi.Void> _ctx;
  bool _finalized = false;

  JustCryptoHashContext._(this._ctx) {
    _streamContextFinalizer.attach(this, _ctx, detach: this);
  }

  /// Adds another chunk to the current streaming state.
  void update(Uint8List data) {
    _checkState();
    withPointer(data, (dataPtr, dataLen) {
      final code = jcStreamUpdate(_ctx, dataPtr, dataLen);
      throwOnFailure(code);
    });
  }

  /// Finalizes the context and returns the resulting digest or MAC bytes.
  Uint8List finalizeHash() {
    _checkState();
    _finalized = true;
    final result = jcStreamFinalize(_ctx);
    _streamContextFinalizer.detach(this);
    _ctx = ffi.Pointer.fromAddress(0); // Mark as freed
    return parseAndFreeResult(result);
  }

  /// Releases the native context early.
  ///
  /// Calling this method is preferred when the lifecycle is explicit. The
  /// native finalizer remains as a safety net for abandoned contexts.
  void dispose() {
    if (!_finalized && _ctx.address != 0) {
      _streamContextFinalizer.detach(this);
      jcStreamFree(_ctx);
      _ctx = ffi.Pointer.fromAddress(0);
      _finalized = true;
    }
  }

  void _checkState() {
    if (_finalized || _ctx.address == 0) {
      throw StateError('Hash context is already finalized or disposed');
    }
  }
}

/// Recommended AEAD entry points for authenticated encryption.
///
/// Example:
/// ```dart
/// final crypto = JustCrypto();
/// final key = crypto.aead.generateAes256GcmKey();
/// final nonce = crypto.aead.generateNonce();
///
/// final ciphertext = crypto.aead.encryptAes256Gcm(
///   message: Uint8List.fromList('hello'.codeUnits),
///   key: key,
///   nonce: nonce,
/// );
/// ```
class JustCryptoAead {
  final JustCrypto _crypto;

  JustCryptoAead._(this._crypto);

  /// Generates a fresh 32-byte key for AES-256-GCM.
  JustCryptoSecretKey generateAes256GcmKey() {
    return JustCryptoSecretKey.aes256(_crypto._generateRandom(32));
  }

  /// Generates a fresh 32-byte key for ChaCha20-Poly1305.
  JustCryptoSecretKey generateChaCha20Poly1305Key() {
    return JustCryptoSecretKey.aes256(_crypto._generateRandom(32));
  }

  /// Generates a fresh 12-byte AEAD nonce.
  JustCryptoNonce generateNonce() {
    return JustCryptoNonce.aead(
      _crypto._generateNonceBytesForAlgorithm(
        algorithm: JustCryptoAlgorithm.aes256Gcm,
      ),
    );
  }

  /// Encrypts [message] with AES-256-GCM.
  Uint8List encryptAes256Gcm({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoNonce nonce,
    Uint8List? aad,
  }) {
    return _crypto._encryptMessage(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: message,
      key: key.bytes,
      nonce: nonce.value,
      aad: aad,
    );
  }

  /// Decrypts [message] produced by [encryptAes256Gcm].
  Uint8List decryptAes256Gcm({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoNonce nonce,
    Uint8List? aad,
  }) {
    return _crypto._decryptMessage(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: message,
      key: key.bytes,
      nonce: nonce.value,
      aad: aad,
    );
  }

  /// Encrypts [message] with ChaCha20-Poly1305.
  Uint8List encryptChaCha20Poly1305({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoNonce nonce,
    Uint8List? aad,
  }) {
    return _crypto._encryptMessage(
      algorithm: JustCryptoAlgorithm.chacha20Poly1305,
      message: message,
      key: key.bytes,
      nonce: nonce.value,
      aad: aad,
    );
  }

  /// Decrypts [message] produced by [encryptChaCha20Poly1305].
  Uint8List decryptChaCha20Poly1305({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoNonce nonce,
    Uint8List? aad,
  }) {
    return _crypto._decryptMessage(
      algorithm: JustCryptoAlgorithm.chacha20Poly1305,
      message: message,
      key: key.bytes,
      nonce: nonce.value,
      aad: aad,
    );
  }

  Future<Uint8List> encryptAes256GcmIsolate({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoNonce nonce,
    Uint8List? aad,
  }) {
    return _crypto.encryptMessageIsolate(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: message,
      key: key.bytes,
      nonce: nonce.value,
      aad: aad,
    );
  }

  Future<Uint8List> decryptAes256GcmIsolate({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoNonce nonce,
    Uint8List? aad,
  }) {
    return _crypto.decryptMessageIsolate(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: message,
      key: key.bytes,
      nonce: nonce.value,
      aad: aad,
    );
  }
}

/// Explicit compatibility surface for CBC-based interoperability.
///
/// CBC does not provide integrity protection. Prefer [JustCryptoAead] for new
/// designs.
class JustCryptoCbcCompatibility {
  final JustCrypto _crypto;

  JustCryptoCbcCompatibility._(this._crypto);

  /// Generates a fresh 16-byte key for AES-128-CBC.
  JustCryptoSecretKey generateAes128Key() {
    return JustCryptoSecretKey.aes128(_crypto._generateRandom(16));
  }

  /// Generates a fresh 32-byte key for AES-256-CBC.
  JustCryptoSecretKey generateAes256Key() {
    return JustCryptoSecretKey.aes256(_crypto._generateRandom(32));
  }

  /// Generates a fresh 16-byte CBC IV.
  JustCryptoIv generateIv() {
    return JustCryptoIv.aesCbc(
      _crypto._generateIvBytesForAlgorithm(
        algorithm: JustCryptoAlgorithm.aes256Cbc,
      ),
    );
  }

  Uint8List encryptAes128Cbc({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoIv iv,
  }) {
    return _crypto._encryptMessage(
      algorithm: JustCryptoAlgorithm.aes128Cbc,
      message: message,
      key: key.bytes,
      iv: iv.value,
    );
  }

  Uint8List decryptAes128Cbc({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoIv iv,
  }) {
    return _crypto._decryptMessage(
      algorithm: JustCryptoAlgorithm.aes128Cbc,
      message: message,
      key: key.bytes,
      iv: iv.value,
    );
  }

  Uint8List encryptAes256Cbc({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoIv iv,
  }) {
    return _crypto._encryptMessage(
      algorithm: JustCryptoAlgorithm.aes256Cbc,
      message: message,
      key: key.bytes,
      iv: iv.value,
    );
  }

  Uint8List decryptAes256Cbc({
    required Uint8List message,
    required JustCryptoSecretKey key,
    required JustCryptoIv iv,
  }) {
    return _crypto._decryptMessage(
      algorithm: JustCryptoAlgorithm.aes256Cbc,
      message: message,
      key: key.bytes,
      iv: iv.value,
    );
  }
}

/// Signature-oriented API that avoids algorithm mismatches in normal use.
///
/// Example:
/// ```dart
/// final crypto = JustCrypto();
/// final pair = crypto.signatures.generateEd25519KeyPair();
/// final message = Uint8List.fromList('sign me'.codeUnits);
/// final signature = crypto.signatures.signEd25519(
///   message: message,
///   privateKey: pair.privateKey,
/// );
/// ```
class JustCryptoSignatures {
  final JustCrypto _crypto;

  JustCryptoSignatures._(this._crypto);

  Ed25519KeyPair generateEd25519KeyPair() {
    final keyPair = _crypto._generateKeyPair(
      algorithm: JustCryptoAlgorithm.ed25519,
    );
    return Ed25519KeyPair(
      publicKey: Ed25519PublicKey(keyPair.publicKey),
      privateKey: Ed25519PrivateKey(keyPair.privateKey),
    );
  }

  Future<Ed25519KeyPair> generateEd25519KeyPairIsolate() async {
    final keyPair = await _crypto.generateKeyPairIsolate(
      algorithm: JustCryptoAlgorithm.ed25519,
    );
    return Ed25519KeyPair(
      publicKey: Ed25519PublicKey(keyPair.publicKey),
      privateKey: Ed25519PrivateKey(keyPair.privateKey),
    );
  }

  JustCryptoSignature signEd25519({
    required Uint8List message,
    required Ed25519PrivateKey privateKey,
  }) {
    return JustCryptoSignature.ed25519(
      _crypto._signMessage(
        algorithm: JustCryptoAlgorithm.ed25519,
        message: message,
        privateKey: privateKey.bytes,
      ),
    );
  }

  Future<JustCryptoSignature> signEd25519Isolate({
    required Uint8List message,
    required Ed25519PrivateKey privateKey,
  }) async {
    final signature = await _crypto.signMessageIsolate(
      algorithm: JustCryptoAlgorithm.ed25519,
      message: message,
      privateKey: privateKey.bytes,
    );
    return JustCryptoSignature.ed25519(signature);
  }

  bool verifyEd25519({
    required Uint8List message,
    required JustCryptoSignature signature,
    required Ed25519PublicKey publicKey,
  }) {
    return _crypto._verifyMessage(
      algorithm: JustCryptoAlgorithm.ed25519,
      message: message,
      signature: signature.value,
      publicKey: publicKey.bytes,
    );
  }

  Future<bool> verifyEd25519Isolate({
    required Uint8List message,
    required JustCryptoSignature signature,
    required Ed25519PublicKey publicKey,
  }) {
    return _crypto.verifyMessageIsolate(
      algorithm: JustCryptoAlgorithm.ed25519,
      message: message,
      signature: signature.value,
      publicKey: publicKey.bytes,
    );
  }
}

/// Key agreement surface specialised for X25519.
class JustCryptoKeyAgreement {
  final JustCrypto _crypto;

  JustCryptoKeyAgreement._(this._crypto);

  X25519KeyPair generateX25519KeyPair() {
    final keyPair = _crypto._generateKeyPair(
      algorithm: JustCryptoAlgorithm.x25519,
    );
    return X25519KeyPair(
      publicKey: X25519PublicKey(keyPair.publicKey),
      privateKey: X25519PrivateKey(keyPair.privateKey),
    );
  }

  Future<X25519KeyPair> generateX25519KeyPairIsolate() async {
    final keyPair = await _crypto.generateKeyPairIsolate(
      algorithm: JustCryptoAlgorithm.x25519,
    );
    return X25519KeyPair(
      publicKey: X25519PublicKey(keyPair.publicKey),
      privateKey: X25519PrivateKey(keyPair.privateKey),
    );
  }

  JustCryptoSharedSecret deriveSharedSecretX25519({
    required X25519PrivateKey privateKey,
    required X25519PublicKey publicKey,
  }) {
    return JustCryptoSharedSecret(
      _crypto._deriveSharedSecret(
        algorithm: JustCryptoAlgorithm.x25519,
        privateKey: privateKey.bytes,
        publicKey: publicKey.bytes,
      ),
    );
  }

  Future<JustCryptoSharedSecret> deriveSharedSecretX25519Isolate({
    required X25519PrivateKey privateKey,
    required X25519PublicKey publicKey,
  }) async {
    final secret = await _crypto.deriveSharedSecretIsolate(
      algorithm: JustCryptoAlgorithm.x25519,
      privateKey: privateKey.bytes,
      publicKey: publicKey.bytes,
    );
    return JustCryptoSharedSecret(secret);
  }
}

/// KDF-oriented API for Argon2id.
///
/// Example:
/// ```dart
/// final crypto = JustCrypto();
/// final salt = crypto.kdf.generateArgon2idSalt();
/// final derived = crypto.kdf.deriveArgon2id(
///   input: Uint8List.fromList('password'.codeUnits),
///   salt: salt,
/// );
/// ```
class JustCryptoKdf {
  final JustCrypto _crypto;

  JustCryptoKdf._(this._crypto);

  JustCryptoSalt generateArgon2idSalt() {
    return JustCryptoSalt.argon2id(
      _crypto._generateSaltBytesForAlgorithm(
        algorithm: JustCryptoAlgorithm.argon2id,
      ),
    );
  }

  Uint8List deriveArgon2id({
    required Uint8List input,
    required JustCryptoSalt salt,
    int memoryCost = 64 * 1024,
    int timeCost = 3,
    int parallelism = 1,
    int outputLength = 32,
  }) {
    return _crypto._deriveKey(
      algorithm: JustCryptoAlgorithm.argon2id,
      input: input,
      salt: salt.value,
      memoryCost: memoryCost,
      timeCost: timeCost,
      parallelism: parallelism,
      outputLength: outputLength,
    );
  }

  Future<Uint8List> deriveArgon2idIsolate({
    required Uint8List input,
    required JustCryptoSalt salt,
    int memoryCost = 64 * 1024,
    int timeCost = 3,
    int parallelism = 1,
    int outputLength = 32,
  }) {
    return _crypto.deriveKeyIsolate(
      algorithm: JustCryptoAlgorithm.argon2id,
      input: input,
      salt: salt.value,
      memoryCost: memoryCost,
      timeCost: timeCost,
      parallelism: parallelism,
      outputLength: outputLength,
    );
  }
}

/// Hash-oriented API for one-shot and streaming digests.
class JustCryptoHashes {
  final JustCrypto _crypto;

  JustCryptoHashes._(this._crypto);

  JustCryptoDigest sha256(Uint8List message) {
    return JustCryptoDigest(
      _crypto._hashMessage(
        algorithm: JustCryptoAlgorithm.sha256,
        message: message,
      ),
    );
  }

  JustCryptoDigest blake3(Uint8List message) {
    return JustCryptoDigest(
      _crypto._hashMessage(
        algorithm: JustCryptoAlgorithm.blake3,
        message: message,
      ),
    );
  }

  Future<JustCryptoDigest> sha256Isolate(Uint8List message) async {
    return JustCryptoDigest(
      await _crypto.hashMessageIsolate(
        algorithm: JustCryptoAlgorithm.sha256,
        message: message,
      ),
    );
  }

  Future<JustCryptoDigest> blake3Isolate(Uint8List message) async {
    return JustCryptoDigest(
      await _crypto.hashMessageIsolate(
        algorithm: JustCryptoAlgorithm.blake3,
        message: message,
      ),
    );
  }

  JustCryptoHashContext createSha256Context() {
    return _crypto._createHashContext(algorithm: JustCryptoAlgorithm.sha256);
  }

  JustCryptoHashContext createBlake3Context() {
    return _crypto._createHashContext(algorithm: JustCryptoAlgorithm.blake3);
  }
}

/// MAC-oriented API for HMAC-SHA256 and secure equality checks.
class JustCryptoMacs {
  final JustCrypto _crypto;

  JustCryptoMacs._(this._crypto);

  /// Generates a fresh key for HMAC-SHA256.
  ///
  /// The default 32-byte length is recommended for new deployments.
  JustCryptoSecretKey generateHmacSha256Key({int length = 32}) {
    if (length < 16) {
      throw const JustCryptoException(
        JustCryptoErrorCodes.invalidKeySize,
        'HMAC-SHA256 keys must be at least 16 bytes.',
      );
    }
    return JustCryptoSecretKey.hmacSha256(_crypto._generateRandom(length));
  }

  JustCryptoDigest hmacSha256({
    required Uint8List message,
    required JustCryptoSecretKey key,
  }) {
    return JustCryptoDigest(
      _crypto._hmacMessage(
        algorithm: JustCryptoAlgorithm.hmacSha256,
        message: message,
        key: key.bytes,
      ),
    );
  }

  Future<JustCryptoDigest> hmacSha256Isolate({
    required Uint8List message,
    required JustCryptoSecretKey key,
  }) async {
    return JustCryptoDigest(
      await _crypto.hmacMessageIsolate(
        algorithm: JustCryptoAlgorithm.hmacSha256,
        message: message,
        key: key.bytes,
      ),
    );
  }

  JustCryptoHashContext createHmacSha256Context({
    required JustCryptoSecretKey key,
  }) {
    return _crypto._createHmacContext(
      algorithm: JustCryptoAlgorithm.hmacSha256,
      key: key.bytes,
    );
  }

  bool constantTimeEquals({required Uint8List left, required Uint8List right}) {
    return _crypto.constantTimeEquals(left: left, right: right);
  }

  Future<bool> constantTimeEqualsIsolate({
    required Uint8List left,
    required Uint8List right,
  }) {
    return _crypto.constantTimeEqualsIsolate(left: left, right: right);
  }
}
