// ignore_for_file: deprecated_member_use

import 'dart:convert';
import 'dart:typed_data';

import 'package:just_crypto/just_crypto.dart';

Future<void> main() async {
  final fixtures = _ExampleFixtures();

  await _runRecommendedApiExample(fixtures);
  await _runCompatibilityApiExample(fixtures);
}

Future<void> _runRecommendedApiExample(_ExampleFixtures fixtures) async {
  final crypto = fixtures.crypto;

  final aesKey = crypto.aead.generateAes256GcmKey();
  final chachaKey = crypto.aead.generateChaCha20Poly1305Key();
  final cbc128Key = crypto.cbc.generateAes128Key();
  final cbc256Key = crypto.cbc.generateAes256Key();
  final hmacKey = crypto.macs.generateHmacSha256Key();

  final nonce = crypto.aead.generateNonce();
  final iv = crypto.cbc.generateIv();
  final salt = crypto.kdf.generateArgon2idSalt();

  final aesGcmCiphertext = crypto.aead.encryptAes256Gcm(
    message: fixtures.message,
    key: aesKey,
    nonce: nonce,
    aad: fixtures.aad,
  );
  final aesGcmPlaintext = crypto.aead.decryptAes256Gcm(
    message: aesGcmCiphertext,
    key: aesKey,
    nonce: nonce,
    aad: fixtures.aad,
  );
  final aesGcmCiphertextIsolate = await crypto.aead.encryptAes256GcmIsolate(
    message: fixtures.message,
    key: aesKey,
    nonce: nonce,
    aad: fixtures.aad,
  );
  final aesGcmPlaintextIsolate = await crypto.aead.decryptAes256GcmIsolate(
    message: aesGcmCiphertext,
    key: aesKey,
    nonce: nonce,
    aad: fixtures.aad,
  );

  final chachaCiphertext = crypto.aead.encryptChaCha20Poly1305(
    message: fixtures.message,
    key: chachaKey,
    nonce: nonce,
    aad: fixtures.aad,
  );
  final chachaPlaintext = crypto.aead.decryptChaCha20Poly1305(
    message: chachaCiphertext,
    key: chachaKey,
    nonce: nonce,
    aad: fixtures.aad,
  );

  final aes128CbcCiphertext = crypto.cbc.encryptAes128Cbc(
    message: fixtures.message,
    key: cbc128Key,
    iv: iv,
  );
  final aes128CbcPlaintext = crypto.cbc.decryptAes128Cbc(
    message: aes128CbcCiphertext,
    key: cbc128Key,
    iv: iv,
  );
  final aes256CbcCiphertext = crypto.cbc.encryptAes256Cbc(
    message: fixtures.message,
    key: cbc256Key,
    iv: iv,
  );
  final aes256CbcPlaintext = crypto.cbc.decryptAes256Cbc(
    message: aes256CbcCiphertext,
    key: cbc256Key,
    iv: iv,
  );

  final ed25519Pair = crypto.signatures.generateEd25519KeyPair();
  final ed25519Signature = crypto.signatures.signEd25519(
    message: fixtures.message,
    privateKey: ed25519Pair.privateKey,
  );
  final ed25519Verified = crypto.signatures.verifyEd25519(
    message: fixtures.message,
    signature: ed25519Signature,
    publicKey: ed25519Pair.publicKey,
  );
  final ed25519PairIsolate = await crypto.signatures
      .generateEd25519KeyPairIsolate();
  final ed25519SignatureIsolate = await crypto.signatures.signEd25519Isolate(
    message: fixtures.message,
    privateKey: ed25519PairIsolate.privateKey,
  );
  final ed25519VerifiedIsolate = await crypto.signatures.verifyEd25519Isolate(
    message: fixtures.message,
    signature: ed25519SignatureIsolate,
    publicKey: ed25519PairIsolate.publicKey,
  );

  final x25519Pair = crypto.keyAgreement.generateX25519KeyPair();
  final x25519Peer = crypto.keyAgreement.generateX25519KeyPair();
  final sharedSecret = crypto.keyAgreement.deriveSharedSecretX25519(
    privateKey: x25519Pair.privateKey,
    publicKey: x25519Peer.publicKey,
  );
  final x25519PairIsolate = await crypto.keyAgreement
      .generateX25519KeyPairIsolate();
  final x25519PeerIsolate = await crypto.keyAgreement
      .generateX25519KeyPairIsolate();
  final sharedSecretIsolate = await crypto.keyAgreement
      .deriveSharedSecretX25519Isolate(
        privateKey: x25519PairIsolate.privateKey,
        publicKey: x25519PeerIsolate.publicKey,
      );

  final derivedKey = crypto.kdf.deriveArgon2id(
    input: fixtures.password,
    salt: salt,
    memoryCost: 64 * 1024,
    timeCost: 3,
    parallelism: 1,
    outputLength: 32,
  );
  final derivedKeyIsolate = await crypto.kdf.deriveArgon2idIsolate(
    input: fixtures.password,
    salt: salt,
    memoryCost: 64 * 1024,
    timeCost: 3,
    parallelism: 1,
    outputLength: 32,
  );

  final sha256 = crypto.hashes.sha256(fixtures.message);
  final blake3 = crypto.hashes.blake3(fixtures.message);
  final sha256Isolate = await crypto.hashes.sha256Isolate(fixtures.message);
  final blake3Isolate = await crypto.hashes.blake3Isolate(fixtures.message);

  final sha256Context = crypto.hashes.createSha256Context();
  sha256Context.update(fixtures.chunkA);
  sha256Context.update(fixtures.chunkB);
  final streamingSha256 = sha256Context.finalizeHash();

  final blake3Context = crypto.hashes.createBlake3Context();
  blake3Context.update(fixtures.chunkA);
  blake3Context.update(fixtures.chunkB);
  final streamingBlake3 = blake3Context.finalizeHash();

  final hmacSha256 = crypto.macs.hmacSha256(
    message: fixtures.message,
    key: hmacKey,
  );
  final hmacSha256Isolate = await crypto.macs.hmacSha256Isolate(
    message: fixtures.message,
    key: hmacKey,
  );

  final hmacContext = crypto.macs.createHmacSha256Context(key: hmacKey);
  hmacContext.update(fixtures.chunkA);
  hmacContext.update(fixtures.chunkB);
  final streamingHmac = hmacContext.finalizeHash();

  final constantTimeEqual = crypto.macs.constantTimeEquals(
    left: hmacSha256.value,
    right: hmacSha256.value,
  );
  final constantTimeEqualIsolate = await crypto.macs.constantTimeEqualsIsolate(
    left: hmacSha256.value,
    right: hmacSha256Isolate.value,
  );

  print('== Recommended API ==');
  print('nonce: ${_hex(nonce.value)}');
  print('iv: ${_hex(iv.value)}');
  print('salt: ${_hex(salt.value)}');
  print('aes256-gcm ciphertext: ${_hex(aesGcmCiphertext)}');
  print('aes256-gcm plaintext: ${utf8.decode(aesGcmPlaintext)}');
  print(
    'aes256-gcm isolate ciphertext bytes: ${aesGcmCiphertextIsolate.length}',
  );
  print('aes256-gcm isolate plaintext: ${utf8.decode(aesGcmPlaintextIsolate)}');
  print('chacha20-poly1305 ciphertext: ${_hex(chachaCiphertext)}');
  print('chacha20-poly1305 plaintext: ${utf8.decode(chachaPlaintext)}');
  print('aes128-cbc ciphertext: ${_hex(aes128CbcCiphertext)}');
  print('aes128-cbc plaintext: ${utf8.decode(aes128CbcPlaintext)}');
  print('aes256-cbc ciphertext: ${_hex(aes256CbcCiphertext)}');
  print('aes256-cbc plaintext: ${utf8.decode(aes256CbcPlaintext)}');
  print('ed25519 public key: ${_hex(ed25519Pair.publicKey.bytes)}');
  print('ed25519 signature: ${_hex(ed25519Signature.value)}');
  print('ed25519 verified: $ed25519Verified');
  print('ed25519 isolate verified: $ed25519VerifiedIsolate');
  print('x25519 shared secret: ${_hex(sharedSecret.value)}');
  print('x25519 isolate shared secret: ${_hex(sharedSecretIsolate.value)}');
  print('argon2id: ${_hex(derivedKey)}');
  print(
    'argon2id isolate matches sync: ${_hex(derivedKey) == _hex(derivedKeyIsolate)}',
  );
  print('sha256: ${_hex(sha256.value)}');
  print('sha256 isolate: ${_hex(sha256Isolate.value)}');
  print('streaming sha256: ${_hex(streamingSha256)}');
  print('blake3: ${_hex(blake3.value)}');
  print('blake3 isolate: ${_hex(blake3Isolate.value)}');
  print('streaming blake3: ${_hex(streamingBlake3)}');
  print('hmac-sha256: ${_hex(hmacSha256.value)}');
  print('hmac-sha256 isolate: ${_hex(hmacSha256Isolate.value)}');
  print('streaming hmac-sha256: ${_hex(streamingHmac)}');
  print('constant-time equals: $constantTimeEqual');
  print('constant-time equals isolate: $constantTimeEqualIsolate');
  print('');
}

Future<void> _runCompatibilityApiExample(_ExampleFixtures fixtures) async {
  final crypto = fixtures.crypto;

  final rawAeadKey = _fixedBytes(32, 1);
  final rawCbc128Key = _fixedBytes(16, 101);
  final rawCbc256Key = _fixedBytes(32, 151);
  final rawNonce = crypto.generateNonce(
    algorithm: JustCryptoAlgorithm.aes256Gcm,
  );
  final rawIv = crypto.generateIv(algorithm: JustCryptoAlgorithm.aes256Cbc);
  final rawSalt = crypto.generateSalt(algorithm: JustCryptoAlgorithm.argon2id);
  final rawHmacKey = crypto.macs.generateHmacSha256Key(length: 32).bytes;

  final aesGcmCiphertext = crypto.encryptMessage(
    algorithm: JustCryptoAlgorithm.aes256Gcm,
    message: fixtures.message,
    key: rawAeadKey,
    nonce: rawNonce,
    aad: fixtures.aad,
  );
  final aesGcmPlaintext = crypto.decryptMessage(
    algorithm: JustCryptoAlgorithm.aes256Gcm,
    message: aesGcmCiphertext,
    key: rawAeadKey,
    nonce: rawNonce,
    aad: fixtures.aad,
  );
  final aesGcmCiphertextIsolate = await crypto.encryptMessageIsolate(
    algorithm: JustCryptoAlgorithm.aes256Gcm,
    message: fixtures.message,
    key: rawAeadKey,
    nonce: rawNonce,
    aad: fixtures.aad,
  );
  final aesGcmPlaintextIsolate = await crypto.decryptMessageIsolate(
    algorithm: JustCryptoAlgorithm.aes256Gcm,
    message: aesGcmCiphertext,
    key: rawAeadKey,
    nonce: rawNonce,
    aad: fixtures.aad,
  );

  final chachaCiphertext = crypto.encryptMessage(
    algorithm: JustCryptoAlgorithm.chacha20Poly1305,
    message: fixtures.message,
    key: rawAeadKey,
    nonce: rawNonce,
    aad: fixtures.aad,
  );
  final chachaPlaintext = crypto.decryptMessage(
    algorithm: JustCryptoAlgorithm.chacha20Poly1305,
    message: chachaCiphertext,
    key: rawAeadKey,
    nonce: rawNonce,
    aad: fixtures.aad,
  );

  final aes128CbcCiphertext = crypto.encryptMessage(
    algorithm: JustCryptoAlgorithm.aes128Cbc,
    message: fixtures.message,
    key: rawCbc128Key,
    iv: rawIv,
  );
  final aes128CbcPlaintext = crypto.decryptMessage(
    algorithm: JustCryptoAlgorithm.aes128Cbc,
    message: aes128CbcCiphertext,
    key: rawCbc128Key,
    iv: rawIv,
  );
  final aes256CbcCiphertext = crypto.encryptMessage(
    algorithm: JustCryptoAlgorithm.aes256Cbc,
    message: fixtures.message,
    key: rawCbc256Key,
    iv: rawIv,
  );
  final aes256CbcPlaintext = crypto.decryptMessage(
    algorithm: JustCryptoAlgorithm.aes256Cbc,
    message: aes256CbcCiphertext,
    key: rawCbc256Key,
    iv: rawIv,
  );

  final rawEd25519Pair = crypto.generateKeyPair(
    algorithm: JustCryptoAlgorithm.ed25519,
  );
  final rawEd25519Signature = crypto.signMessage(
    algorithm: JustCryptoAlgorithm.ed25519,
    message: fixtures.message,
    privateKey: rawEd25519Pair.privateKey,
  );
  final rawEd25519Verified = crypto.verifyMessage(
    algorithm: JustCryptoAlgorithm.ed25519,
    message: fixtures.message,
    signature: rawEd25519Signature,
    publicKey: rawEd25519Pair.publicKey,
  );
  final rawEd25519PairIsolate = await crypto.generateKeyPairIsolate(
    algorithm: JustCryptoAlgorithm.ed25519,
  );
  final rawEd25519SignatureIsolate = await crypto.signMessageIsolate(
    algorithm: JustCryptoAlgorithm.ed25519,
    message: fixtures.message,
    privateKey: rawEd25519PairIsolate.privateKey,
  );
  final rawEd25519VerifiedIsolate = await crypto.verifyMessageIsolate(
    algorithm: JustCryptoAlgorithm.ed25519,
    message: fixtures.message,
    signature: rawEd25519SignatureIsolate,
    publicKey: rawEd25519PairIsolate.publicKey,
  );

  final rawX25519Alice = crypto.generateKeyPair(
    algorithm: JustCryptoAlgorithm.x25519,
  );
  final rawX25519Bob = crypto.generateKeyPair(
    algorithm: JustCryptoAlgorithm.x25519,
  );
  final rawSharedSecret = crypto.deriveSharedSecret(
    algorithm: JustCryptoAlgorithm.x25519,
    privateKey: rawX25519Alice.privateKey,
    publicKey: rawX25519Bob.publicKey,
  );
  final rawX25519AliceIsolate = await crypto.generateKeyPairIsolate(
    algorithm: JustCryptoAlgorithm.x25519,
  );
  final rawX25519BobIsolate = await crypto.generateKeyPairIsolate(
    algorithm: JustCryptoAlgorithm.x25519,
  );
  final rawSharedSecretIsolate = await crypto.deriveSharedSecretIsolate(
    algorithm: JustCryptoAlgorithm.x25519,
    privateKey: rawX25519AliceIsolate.privateKey,
    publicKey: rawX25519BobIsolate.publicKey,
  );

  final rawDerivedKey = crypto.deriveKey(
    algorithm: JustCryptoAlgorithm.argon2id,
    input: fixtures.password,
    salt: rawSalt,
    memoryCost: 64 * 1024,
    timeCost: 3,
    parallelism: 1,
    outputLength: 32,
  );
  final rawDerivedKeyIsolate = await crypto.deriveKeyIsolate(
    algorithm: JustCryptoAlgorithm.argon2id,
    input: fixtures.password,
    salt: rawSalt,
    memoryCost: 64 * 1024,
    timeCost: 3,
    parallelism: 1,
    outputLength: 32,
  );

  final rawSha256 = crypto.hashMessage(
    algorithm: JustCryptoAlgorithm.sha256,
    message: fixtures.message,
  );
  final rawSha256Isolate = await crypto.hashMessageIsolate(
    algorithm: JustCryptoAlgorithm.sha256,
    message: fixtures.message,
  );
  final rawBlake3 = crypto.hashMessage(
    algorithm: JustCryptoAlgorithm.blake3,
    message: fixtures.message,
  );
  final rawBlake3Isolate = await crypto.hashMessageIsolate(
    algorithm: JustCryptoAlgorithm.blake3,
    message: fixtures.message,
  );

  final rawShaContext = crypto.createHashContext(
    algorithm: JustCryptoAlgorithm.sha256,
  );
  rawShaContext.update(fixtures.chunkA);
  rawShaContext.update(fixtures.chunkB);
  final rawStreamingSha = rawShaContext.finalizeHash();

  final rawBlakeContext = crypto.createHashContext(
    algorithm: JustCryptoAlgorithm.blake3,
  );
  rawBlakeContext.update(fixtures.chunkA);
  rawBlakeContext.update(fixtures.chunkB);
  final rawStreamingBlake = rawBlakeContext.finalizeHash();

  final rawHmac = crypto.hmacMessage(
    algorithm: JustCryptoAlgorithm.hmacSha256,
    message: fixtures.message,
    key: rawHmacKey,
  );
  final rawHmacIsolate = await crypto.hmacMessageIsolate(
    algorithm: JustCryptoAlgorithm.hmacSha256,
    message: fixtures.message,
    key: rawHmacKey,
  );
  final rawHmacContext = crypto.createHmacContext(
    algorithm: JustCryptoAlgorithm.hmacSha256,
    key: rawHmacKey,
  );
  rawHmacContext.update(fixtures.chunkA);
  rawHmacContext.update(fixtures.chunkB);
  final rawStreamingHmac = rawHmacContext.finalizeHash();

  final rawConstantTimeEqual = crypto.constantTimeEquals(
    left: rawHmac,
    right: rawHmac,
  );
  final rawConstantTimeEqualIsolate = await crypto.constantTimeEqualsIsolate(
    left: rawHmac,
    right: rawHmacIsolate,
  );

  print('== Compatibility API ==');
  print('raw nonce: ${_hex(rawNonce)}');
  print('raw iv: ${_hex(rawIv)}');
  print('raw salt: ${_hex(rawSalt)}');
  print('raw aes256-gcm ciphertext: ${_hex(aesGcmCiphertext)}');
  print('raw aes256-gcm plaintext: ${utf8.decode(aesGcmPlaintext)}');
  print(
    'raw aes256-gcm isolate ciphertext bytes: ${aesGcmCiphertextIsolate.length}',
  );
  print(
    'raw aes256-gcm isolate plaintext: ${utf8.decode(aesGcmPlaintextIsolate)}',
  );
  print('raw chacha20-poly1305 ciphertext: ${_hex(chachaCiphertext)}');
  print('raw chacha20-poly1305 plaintext: ${utf8.decode(chachaPlaintext)}');
  print('raw aes128-cbc plaintext: ${utf8.decode(aes128CbcPlaintext)}');
  print('raw aes256-cbc plaintext: ${utf8.decode(aes256CbcPlaintext)}');
  print('raw ed25519 verified: $rawEd25519Verified');
  print('raw ed25519 isolate verified: $rawEd25519VerifiedIsolate');
  print('raw x25519 shared secret: ${_hex(rawSharedSecret)}');
  print('raw x25519 isolate shared secret: ${_hex(rawSharedSecretIsolate)}');
  print('raw argon2id: ${_hex(rawDerivedKey)}');
  print(
    'raw argon2id isolate matches sync: ${_hex(rawDerivedKey) == _hex(rawDerivedKeyIsolate)}',
  );
  print('raw sha256: ${_hex(rawSha256)}');
  print('raw sha256 isolate: ${_hex(rawSha256Isolate)}');
  print('raw streaming sha256: ${_hex(rawStreamingSha)}');
  print('raw blake3: ${_hex(rawBlake3)}');
  print('raw blake3 isolate: ${_hex(rawBlake3Isolate)}');
  print('raw streaming blake3: ${_hex(rawStreamingBlake)}');
  print('raw hmac-sha256: ${_hex(rawHmac)}');
  print('raw hmac-sha256 isolate: ${_hex(rawHmacIsolate)}');
  print('raw streaming hmac-sha256: ${_hex(rawStreamingHmac)}');
  print('raw constant-time equals: $rawConstantTimeEqual');
  print('raw constant-time equals isolate: $rawConstantTimeEqualIsolate');
  print('raw ed25519 public key: ${_hex(rawEd25519Pair.publicKey)}');
  print('raw ed25519 signature: ${_hex(rawEd25519Signature)}');
  print('raw aes128-cbc ciphertext: ${_hex(aes128CbcCiphertext)}');
  print('raw aes256-cbc ciphertext: ${_hex(aes256CbcCiphertext)}');
  print('');
}

class _ExampleFixtures {
  final JustCrypto crypto = JustCrypto();
  final Uint8List message = Uint8List.fromList(
    utf8.encode('just_crypto example message for the full public API'),
  );
  final Uint8List aad = Uint8List.fromList(utf8.encode('example-aad'));
  final Uint8List password = Uint8List.fromList(
    utf8.encode('correct horse battery staple'),
  );
  final Uint8List chunkA = Uint8List.fromList(utf8.encode('just_'));
  late final Uint8List chunkB = Uint8List.fromList(
    utf8.encode('crypto example message for the full public API'),
  );
}

Uint8List _fixedBytes(int length, int seed) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (seed + (index * 17)) & 0xff),
  );
}

String _hex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
