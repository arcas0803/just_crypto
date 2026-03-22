import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as reference;
import 'package:cryptography/dart.dart' as pure_dart;
import 'package:just_crypto/just_crypto.dart';
import 'package:test/test.dart';

Uint8List generatedBytes(int length, int seed) {
  return Uint8List.fromList(
    List<int>.generate(
      length,
      (index) => (seed + (index * 29) + length) & 0xff,
    ),
  );
}

Uint8List combinedCiphertext(reference.SecretBox box) {
  return Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
}

reference.SecretBox splitCombinedCiphertext(Uint8List value, Uint8List nonce) {
  return reference.SecretBox(
    value.sublist(0, value.length - 16),
    nonce: nonce,
    mac: reference.Mac(value.sublist(value.length - 16)),
  );
}

void main() {
  group('just_crypto professional surface', () {
    final crypto = JustCrypto();
    final message = Uint8List.fromList(
      utf8.encode('professional regression message'),
    );
    final aad = Uint8List.fromList([9, 8, 7, 6]);
    final aes256KeyBytes = Uint8List.fromList(
      List<int>.generate(32, (index) => index),
    );
    final aes128KeyBytes = Uint8List.fromList(
      List<int>.generate(16, (index) => index),
    );
    final aes256CbcKeyBytes = Uint8List.fromList(
      List<int>.generate(32, (index) => 31 - index),
    );
    final nonceBytes = Uint8List.fromList(
      List<int>.generate(12, (index) => index + 1),
    );
    final ivBytes = Uint8List.fromList(
      List<int>.generate(16, (index) => 15 - index),
    );
    final password = Uint8List.fromList(
      utf8.encode('correct horse battery staple'),
    );
    final saltBytes = Uint8List.fromList(
      List<int>.generate(16, (index) => index + 16),
    );
    final hmacVectorMessage = Uint8List.fromList('Hi There'.codeUnits);
    final hmacKeyBytes = Uint8List.fromList(List<int>.filled(20, 0x0b));

    final aeadKey = JustCryptoSecretKey.aes256(aes256KeyBytes);
    final cbc128Key = JustCryptoSecretKey.aes128(aes128KeyBytes);
    final cbc256Key = JustCryptoSecretKey.aes256(aes256CbcKeyBytes);
    final hmacKey = JustCryptoSecretKey.hmacSha256(
      Uint8List.fromList(List<int>.filled(32, 0x0b)),
    );
    final nonce = JustCryptoNonce.aead(nonceBytes);
    final iv = JustCryptoIv.aesCbc(ivBytes);
    final salt = JustCryptoSalt.argon2id(saltBytes);

    String toHex(List<int> bytes) {
      return bytes
          .map((value) => value.toRadixString(16).padLeft(2, '0'))
          .join();
    }

    test('recommended AEAD API decrypts its own ciphertext', () {
      final ciphertext = crypto.aead.encryptAes256Gcm(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );
      final plaintext = crypto.aead.decryptAes256Gcm(
        message: ciphertext,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );

      expect(plaintext, orderedEquals(message));
    });

    test('domain generators return correctly typed material', () {
      final generatedAeadKey = crypto.aead.generateAes256GcmKey();
      final generatedChaChaKey = crypto.aead.generateChaCha20Poly1305Key();
      final generatedNonce = crypto.aead.generateNonce();
      final generatedAes128Key = crypto.cbc.generateAes128Key();
      final generatedAes256Key = crypto.cbc.generateAes256Key();
      final generatedIv = crypto.cbc.generateIv();
      final generatedHmacKey = crypto.macs.generateHmacSha256Key();

      expect(generatedAeadKey.bytes, hasLength(32));
      expect(generatedChaChaKey.bytes, hasLength(32));
      expect(generatedNonce.value, hasLength(12));
      expect(generatedAes128Key.bytes, hasLength(16));
      expect(generatedAes256Key.bytes, hasLength(32));
      expect(generatedIv.value, hasLength(16));
      expect(generatedHmacKey.bytes, hasLength(32));
    });

    test('documentation-style workflow succeeds without generic helpers', () {
      final generatedKey = crypto.aead.generateAes256GcmKey();
      final generatedNonce = crypto.aead.generateNonce();
      final generatedCiphertext = crypto.aead.encryptAes256Gcm(
        message: message,
        key: generatedKey,
        nonce: generatedNonce,
      );

      final generatedPlaintext = crypto.aead.decryptAes256Gcm(
        message: generatedCiphertext,
        key: generatedKey,
        nonce: generatedNonce,
      );

      expect(generatedPlaintext, orderedEquals(message));
    });

    test('legacy and recommended AEAD APIs are equivalent', () {
      final legacy = crypto.encryptMessage(
        algorithm: JustCryptoAlgorithm.aes256Gcm,
        message: message,
        key: aes256KeyBytes,
        nonce: nonceBytes,
        aad: aad,
      );
      final recommended = crypto.aead.encryptAes256Gcm(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );

      expect(recommended, orderedEquals(legacy));
    });

    test('AES-256-GCM regression vector is stable', () {
      final ciphertext = crypto.aead.encryptAes256Gcm(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );

      expect(
        toHex(ciphertext),
        '759835b389e783ef23cc022b30618f4f3026928dfe023ee5cc3a8a57ffd113d762ff4a40ccea52e7aa053db9fef458',
      );
    });

    test('ChaCha20-Poly1305 regression vector is stable', () {
      final ciphertext = crypto.aead.encryptChaCha20Poly1305(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );

      expect(
        toHex(ciphertext),
        '14fa2b0c6c21d7da2787242bf4d3e969cc99e0ed2fe6d16b16b8dfba27888adc9618c49079b61ff8a25143b45b6bf2',
      );
    });

    test('AES-256-GCM interoperates with package:cryptography', () {
      final referenceAlgorithm = pure_dart.DartAesGcm.with256bits();
      final referenceKey = reference.SecretKeyData(aes256KeyBytes);

      final justCiphertext = crypto.aead.encryptAes256Gcm(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );
      final referenceCiphertext = referenceAlgorithm.encryptSync(
        message,
        secretKeyData: referenceKey,
        nonce: nonce.value,
        aad: aad,
      );

      expect(
        justCiphertext,
        orderedEquals(combinedCiphertext(referenceCiphertext)),
      );
      expect(
        referenceAlgorithm.decryptSync(
          splitCombinedCiphertext(justCiphertext, nonce.value),
          secretKeyData: referenceKey,
          aad: aad,
        ),
        orderedEquals(message),
      );
    });

    test('ChaCha20-Poly1305 interoperates with package:cryptography', () {
      final referenceAlgorithm = const pure_dart.DartChacha20.poly1305Aead();
      final referenceKey = reference.SecretKeyData(aes256KeyBytes);

      final justCiphertext = crypto.aead.encryptChaCha20Poly1305(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );
      final referenceCiphertext = referenceAlgorithm.encryptSync(
        message,
        secretKey: referenceKey,
        nonce: nonce.value,
        aad: aad,
      );

      expect(
        justCiphertext,
        orderedEquals(combinedCiphertext(referenceCiphertext)),
      );
      expect(
        referenceAlgorithm.decryptSync(
          splitCombinedCiphertext(justCiphertext, nonce.value),
          secretKey: referenceKey,
          aad: aad,
        ),
        orderedEquals(message),
      );
    });

    test('AES-128-CBC regression vector is stable', () {
      final ciphertext = crypto.cbc.encryptAes128Cbc(
        message: message,
        key: cbc128Key,
        iv: iv,
      );

      expect(
        toHex(ciphertext),
        'c4d5f2bf0f919e97ecca319a28bf9e13928307ab09121246573a337095d5e775',
      );
    });

    test('AES-256-CBC regression vector is stable', () {
      final ciphertext = crypto.cbc.encryptAes256Cbc(
        message: message,
        key: cbc256Key,
        iv: iv,
      );

      expect(
        toHex(ciphertext),
        '3a2300e7be09bd48917d56c35d5bb4d945c5a56f4b52627e2505b51fad73f64a',
      );
    });

    test('Argon2id regression vector is stable', () {
      final derived = crypto.kdf.deriveArgon2id(
        input: password,
        salt: salt,
        memoryCost: 32 * 1024,
        timeCost: 2,
        parallelism: 1,
        outputLength: 32,
      );

      expect(
        toHex(derived),
        '589d1c20e71e4a8265786398d4cbcebdc8939a2ef802d5709d6ff9b3283c78e9',
      );
    });

    test('SHA-256 known regression vector is stable', () {
      final digest = crypto.hashes.sha256(message);
      expect(
        toHex(digest.value),
        '08ab6993a6c719cefc2ad069cd2d7f919769a1417f89fe4daa3fa2c7084796a5',
      );
    });

    test('SHA-256 interoperates with package:cryptography', () {
      final referenceAlgorithm = const pure_dart.DartSha256();
      final referenceDigest = referenceAlgorithm.hashSync(message);

      expect(
        crypto.hashes.sha256(message).value,
        orderedEquals(Uint8List.fromList(referenceDigest.bytes)),
      );
    });

    test('BLAKE3 regression vector is stable', () {
      final digest = crypto.hashes.blake3(message);
      expect(
        toHex(digest.value),
        '507e8036589c9aa94da82d66b7ac63befac2c309c974e92cd412f2bbb9a468b7',
      );
    });

    test('HMAC-SHA256 known regression vector is stable', () {
      final mac = crypto.hmacMessage(
        algorithm: JustCryptoAlgorithm.hmacSha256,
        message: hmacVectorMessage,
        key: hmacKeyBytes,
      );

      expect(
        toHex(mac),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
      );
    });

    test('HMAC-SHA256 interoperates with package:cryptography', () {
      final referenceAlgorithm = pure_dart.DartHmac.sha256();
      final referenceMac = referenceAlgorithm.calculateMacSync(
        message,
        secretKeyData: reference.SecretKeyData(hmacKey.bytes),
        nonce: const <int>[],
      );

      expect(
        crypto.macs.hmacSha256(message: message, key: hmacKey).value,
        orderedEquals(Uint8List.fromList(referenceMac.bytes)),
      );
    });

    test('Ed25519 interoperates with package:cryptography', () async {
      final referenceAlgorithm = pure_dart.DartEd25519();
      final seed = generatedBytes(32, 211);
      final keyPair = await referenceAlgorithm.newKeyPairFromSeed(seed);
      final publicKey = await keyPair.extractPublicKey();
      final referenceSignature = await referenceAlgorithm.sign(
        message,
        keyPair: keyPair,
      );

      final justSignature = crypto.signatures.signEd25519(
        message: message,
        privateKey: Ed25519PrivateKey(seed),
      );

      expect(justSignature.value, orderedEquals(referenceSignature.bytes));
      expect(
        crypto.signatures.verifyEd25519(
          message: message,
          signature: JustCryptoSignature.ed25519(
            Uint8List.fromList(referenceSignature.bytes),
          ),
          publicKey: Ed25519PublicKey(Uint8List.fromList(publicKey.bytes)),
        ),
        isTrue,
      );
    });

    test('Ed25519 domain API signs and verifies', () {
      final pair = crypto.signatures.generateEd25519KeyPair();
      final signature = crypto.signatures.signEd25519(
        message: message,
        privateKey: pair.privateKey,
      );

      expect(
        crypto.signatures.verifyEd25519(
          message: message,
          signature: signature,
          publicKey: pair.publicKey,
        ),
        isTrue,
      );

      final tampered = Uint8List.fromList(signature.value);
      tampered[0] ^= 0x01;

      expect(
        crypto.verifyMessage(
          algorithm: JustCryptoAlgorithm.ed25519,
          message: message,
          signature: tampered,
          publicKey: pair.publicKey.bytes,
        ),
        isFalse,
      );
    });

    test('X25519 shared secret is symmetric through the domain API', () {
      final alice = crypto.keyAgreement.generateX25519KeyPair();
      final bob = crypto.keyAgreement.generateX25519KeyPair();

      final aliceSecret = crypto.keyAgreement.deriveSharedSecretX25519(
        privateKey: alice.privateKey,
        publicKey: bob.publicKey,
      );
      final bobSecret = crypto.keyAgreement.deriveSharedSecretX25519(
        privateKey: bob.privateKey,
        publicKey: alice.publicKey,
      );

      expect(aliceSecret.value, orderedEquals(bobSecret.value));
    });

    test('AEAD roundtrips across multiple payload sizes', () {
      for (final length in [0, 1, 15, 16, 31, 32, 127, 1024]) {
        final localMessage = generatedBytes(length, 17 + length);
        final localAad = generatedBytes(length % 19, 33 + length);
        final localKey = JustCryptoSecretKey.aes256(
          generatedBytes(32, 51 + length),
        );
        final localNonce = JustCryptoNonce.aead(
          generatedBytes(12, 79 + length),
        );

        final aesCiphertext = crypto.aead.encryptAes256Gcm(
          message: localMessage,
          key: localKey,
          nonce: localNonce,
          aad: localAad,
        );
        final chachaCiphertext = crypto.aead.encryptChaCha20Poly1305(
          message: localMessage,
          key: localKey,
          nonce: localNonce,
          aad: localAad,
        );

        expect(
          crypto.aead.decryptAes256Gcm(
            message: aesCiphertext,
            key: localKey,
            nonce: localNonce,
            aad: localAad,
          ),
          orderedEquals(localMessage),
        );
        expect(
          crypto.aead.decryptChaCha20Poly1305(
            message: chachaCiphertext,
            key: localKey,
            nonce: localNonce,
            aad: localAad,
          ),
          orderedEquals(localMessage),
        );
      }
    });

    test('AEAD tampering is rejected across supported algorithms', () {
      final aesCiphertext = crypto.aead.encryptAes256Gcm(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );
      final chachaCiphertext = crypto.aead.encryptChaCha20Poly1305(
        message: message,
        key: aeadKey,
        nonce: nonce,
        aad: aad,
      );

      final tamperedAes = Uint8List.fromList(aesCiphertext)..[0] ^= 0x01;
      final tamperedChacha = Uint8List.fromList(chachaCiphertext);
      tamperedChacha[tamperedChacha.length - 1] ^= 0x01;

      expect(
        () => crypto.aead.decryptAes256Gcm(
          message: tamperedAes,
          key: aeadKey,
          nonce: nonce,
          aad: aad,
        ),
        throwsA(isA<JustCryptoException>()),
      );
      expect(
        () => crypto.aead.decryptChaCha20Poly1305(
          message: tamperedChacha,
          key: aeadKey,
          nonce: nonce,
          aad: aad,
        ),
        throwsA(isA<JustCryptoException>()),
      );
    });

    test('CBC roundtrips across variable payload sizes', () {
      for (final length in [0, 1, 15, 16, 17, 31, 32, 63, 128]) {
        final localMessage = generatedBytes(length, 141 + length);
        final localAes128Key = JustCryptoSecretKey.aes128(
          generatedBytes(16, 171 + length),
        );
        final localAes256Key = JustCryptoSecretKey.aes256(
          generatedBytes(32, 201 + length),
        );
        final localIv = JustCryptoIv.aesCbc(generatedBytes(16, 231 + length));

        final aes128Ciphertext = crypto.cbc.encryptAes128Cbc(
          message: localMessage,
          key: localAes128Key,
          iv: localIv,
        );
        final aes256Ciphertext = crypto.cbc.encryptAes256Cbc(
          message: localMessage,
          key: localAes256Key,
          iv: localIv,
        );

        expect(
          crypto.cbc.decryptAes128Cbc(
            message: aes128Ciphertext,
            key: localAes128Key,
            iv: localIv,
          ),
          orderedEquals(localMessage),
        );
        expect(
          crypto.cbc.decryptAes256Cbc(
            message: aes256Ciphertext,
            key: localAes256Key,
            iv: localIv,
          ),
          orderedEquals(localMessage),
        );
      }
    });

    test('hash isolate matches sync output', () async {
      final syncDigest = crypto.hashes.sha256(message);
      final isolateDigest = await crypto.hashes.sha256Isolate(message);
      expect(isolateDigest.value, orderedEquals(syncDigest.value));
    });

    test('HMAC isolate matches sync output', () async {
      final syncMac = crypto.macs.hmacSha256(message: message, key: hmacKey);
      final isolateMac = await crypto.macs.hmacSha256Isolate(
        message: message,
        key: hmacKey,
      );
      expect(isolateMac.value, orderedEquals(syncMac.value));
    });

    test('constant-time compare returns stable bool results', () async {
      final left = crypto.hashes.sha256(message).value;
      final right = Uint8List.fromList(left);
      final different = Uint8List.fromList(left)..[0] ^= 0x01;

      expect(crypto.macs.constantTimeEquals(left: left, right: right), isTrue);
      expect(
        crypto.macs.constantTimeEquals(left: left, right: different),
        isFalse,
      );
      expect(
        await crypto.macs.constantTimeEqualsIsolate(left: left, right: right),
        isTrue,
      );
    });

    test('streaming hash matches one-shot hash', () {
      final context = crypto.hashes.createSha256Context();
      context.update(Uint8List.fromList(utf8.encode('professional ')));
      context.update(Uint8List.fromList(utf8.encode('regression message')));

      expect(
        context.finalizeHash(),
        orderedEquals(crypto.hashes.sha256(message).value),
      );
    });

    test('streaming HMAC matches one-shot HMAC', () {
      final context = crypto.macs.createHmacSha256Context(key: hmacKey);
      context.update(Uint8List.fromList(utf8.encode('professional ')));
      context.update(Uint8List.fromList(utf8.encode('regression message')));

      expect(
        context.finalizeHash(),
        orderedEquals(
          crypto.macs.hmacSha256(message: message, key: hmacKey).value,
        ),
      );
    });

    test('streaming digests remain stable across chunk boundaries', () {
      final largeMessage = generatedBytes(513, 77);

      for (final chunkSize in [1, 2, 3, 5, 8, 13, 64, 128]) {
        final shaContext = crypto.hashes.createSha256Context();
        final blakeContext = crypto.hashes.createBlake3Context();
        final hmacContext = crypto.macs.createHmacSha256Context(key: hmacKey);

        for (
          var offset = 0;
          offset < largeMessage.length;
          offset += chunkSize
        ) {
          final end = (offset + chunkSize < largeMessage.length)
              ? offset + chunkSize
              : largeMessage.length;
          final chunk = Uint8List.fromList(largeMessage.sublist(offset, end));
          shaContext.update(chunk);
          blakeContext.update(chunk);
          hmacContext.update(chunk);
        }

        expect(
          shaContext.finalizeHash(),
          orderedEquals(crypto.hashes.sha256(largeMessage).value),
        );
        expect(
          blakeContext.finalizeHash(),
          orderedEquals(crypto.hashes.blake3(largeMessage).value),
        );
        expect(
          hmacContext.finalizeHash(),
          orderedEquals(
            crypto.macs.hmacSha256(message: largeMessage, key: hmacKey).value,
          ),
        );
      }
    });

    test('context cannot be reused after finalize', () {
      final context = crypto.hashes.createSha256Context();
      context.update(Uint8List.fromList([1, 2, 3]));
      context.finalizeHash();

      expect(
        () => context.update(Uint8List.fromList([4, 5, 6])),
        throwsA(isA<StateError>()),
      );
    });

    test('typed wrappers reject invalid input lengths', () {
      expect(
        () => JustCryptoNonce.aead(Uint8List.fromList([1, 2, 3])),
        throwsA(
          isA<JustCryptoException>().having(
            (error) => error.code,
            'code',
            JustCryptoErrorCodes.invalidNonceSize,
          ),
        ),
      );

      expect(
        () => JustCryptoSalt.argon2id(Uint8List.fromList([1, 2, 3])),
        throwsA(
          isA<JustCryptoException>().having(
            (error) => error.code,
            'code',
            JustCryptoErrorCodes.invalidSaltSize,
          ),
        ),
      );
    });

    test('invalid salt size is rejected before crossing FFI', () {
      expect(
        () => crypto.deriveKey(
          algorithm: JustCryptoAlgorithm.argon2id,
          input: password,
          salt: Uint8List.fromList([1, 2, 3]),
          outputLength: 32,
        ),
        throwsA(
          isA<JustCryptoException>().having(
            (error) => error.code,
            'code',
            JustCryptoErrorCodes.invalidSaltSize,
          ),
        ),
      );
    });

    test('CBC rejects invalid IV sizes before crossing FFI', () {
      expect(
        () => JustCryptoIv.aesCbc(Uint8List.fromList([1, 2, 3])),
        throwsA(
          isA<JustCryptoException>().having(
            (error) => error.code,
            'code',
            JustCryptoErrorCodes.invalidIvSize,
          ),
        ),
      );
    });
  });
}
