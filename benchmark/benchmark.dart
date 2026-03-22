import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as reference;
import 'package:cryptography/dart.dart' as pure_dart;
import 'package:just_crypto/just_crypto.dart';

Future<void> main() async {
  final crypto = JustCrypto();
  final message4k = _bytes(4096, 7);
  final message64k = _bytes(64 * 1024, 19);
  final signatureMessage = Uint8List.fromList(
    utf8.encode('benchmark: ed25519 signature payload'),
  );
  final aad = Uint8List.fromList(utf8.encode('benchmark-aad'));
  final aesKey = _bytes(32, 31);
  final chachaKey = _bytes(32, 63);
  final hmacKey = _bytes(32, 95);
  final nonce = _bytes(12, 127);
  final password = Uint8List.fromList(utf8.encode('benchmark-password'));
  final salt = _bytes(16, 159);

  final pureAes = pure_dart.DartAesGcm.with256bits();
  final pureAesKey = reference.SecretKeyData(aesKey);
  final pureChacha = const pure_dart.DartChacha20.poly1305Aead();
  final pureChachaKey = reference.SecretKeyData(chachaKey);
  final pureSha256 = const pure_dart.DartSha256();
  final pureHmac = pure_dart.DartHmac.sha256();
  final pureEd25519 = pure_dart.DartEd25519();
  final pureEd25519Seed = _bytes(32, 191);
  final pureEd25519KeyPair = await pureEd25519.newKeyPairFromSeed(
    pureEd25519Seed,
  );
  final pureEd25519PublicKey = await pureEd25519KeyPair.extractPublicKey();

  final justEd25519Pair = crypto.generateKeyPair(
    algorithm: JustCryptoAlgorithm.ed25519,
  );
  final referenceKeyPairFromJustSeed = await pureEd25519.newKeyPairFromSeed(
    justEd25519Pair.privateKey,
  );
  final referenceKeyPairFromJustPublic = await referenceKeyPairFromJustSeed
      .extractPublicKey();

  final aesCipherJust = crypto.encryptMessage(
    algorithm: JustCryptoAlgorithm.aes256Gcm,
    message: message4k,
    key: aesKey,
    nonce: nonce,
    aad: aad,
  );
  final aesCipherPure = pureAes.encryptSync(
    message4k,
    secretKeyData: pureAesKey,
    nonce: nonce,
    aad: aad,
  );
  _expectEqual(
    'AES-256-GCM encrypt',
    aesCipherJust,
    Uint8List.fromList([
      ...aesCipherPure.cipherText,
      ...aesCipherPure.mac.bytes,
    ]),
  );
  _expectEqual(
    'AES-256-GCM decrypt',
    crypto.decryptMessage(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: aesCipherJust,
      key: aesKey,
      nonce: nonce,
      aad: aad,
    ),
    Uint8List.fromList(
      pureAes.decryptSync(aesCipherPure, secretKeyData: pureAesKey, aad: aad),
    ),
  );

  final chachaCipherJust = crypto.encryptMessage(
    algorithm: JustCryptoAlgorithm.chacha20Poly1305,
    message: message4k,
    key: chachaKey,
    nonce: nonce,
    aad: aad,
  );
  final chachaCipherPure = pureChacha.encryptSync(
    message4k,
    secretKey: pureChachaKey,
    nonce: nonce,
    aad: aad,
  );
  _expectEqual(
    'ChaCha20-Poly1305 encrypt',
    chachaCipherJust,
    Uint8List.fromList([
      ...chachaCipherPure.cipherText,
      ...chachaCipherPure.mac.bytes,
    ]),
  );
  _expectEqual(
    'ChaCha20-Poly1305 decrypt',
    crypto.decryptMessage(
      algorithm: JustCryptoAlgorithm.chacha20Poly1305,
      message: chachaCipherJust,
      key: chachaKey,
      nonce: nonce,
      aad: aad,
    ),
    Uint8List.fromList(
      pureChacha.decryptSync(
        chachaCipherPure,
        secretKey: pureChachaKey,
        aad: aad,
      ),
    ),
  );

  _expectEqual(
    'SHA-256 hash',
    crypto.hashMessage(
      algorithm: JustCryptoAlgorithm.sha256,
      message: message64k,
    ),
    Uint8List.fromList(pureSha256.hashSync(message64k).bytes),
  );
  _expectEqual(
    'HMAC-SHA256',
    crypto.hmacMessage(
      algorithm: JustCryptoAlgorithm.hmacSha256,
      message: message64k,
      key: hmacKey,
    ),
    Uint8List.fromList(
      pureHmac
          .calculateMacSync(
            message64k,
            secretKeyData: reference.SecretKeyData(hmacKey),
            nonce: const <int>[],
          )
          .bytes,
    ),
  );

  final justSignature = crypto.signMessage(
    algorithm: JustCryptoAlgorithm.ed25519,
    message: signatureMessage,
    privateKey: justEd25519Pair.privateKey,
  );
  final pureSignatureFromJustSeed = await pureEd25519.sign(
    signatureMessage,
    keyPair: referenceKeyPairFromJustSeed,
  );
  _expectEqual(
    'Ed25519 signature',
    justSignature,
    Uint8List.fromList(pureSignatureFromJustSeed.bytes),
  );
  final pureSignBenchmarkSignature = await pureEd25519.sign(
    signatureMessage,
    keyPair: pureEd25519KeyPair,
  );
  final justArgon = crypto.deriveKey(
    algorithm: JustCryptoAlgorithm.argon2id,
    input: password,
    salt: salt,
    memoryCost: 16 * 1024,
    timeCost: 2,
    parallelism: 1,
    outputLength: 32,
  );

  print('# just_crypto benchmark');
  print('');
  print('Machine: macOS arm64');
  print('Runtime: Dart 3.11.3');
  print('Reference library: package:cryptography pure Dart implementations');
  print('');
  print(
    '| Operation | Payload | just_crypto sync | just_crypto isolate | pure Dart | Speedup |',
  );
  print('| --- | ---: | ---: | ---: | ---: | ---: |');

  await _printSyncComparison(
    name: 'AES-256-GCM encrypt',
    payload: '4 KiB',
    syncIterations: 300,
    isolateIterations: 40,
    justCryptoSync: () {
      crypto.encryptMessage(
        algorithm: JustCryptoAlgorithm.aes256Gcm,
        message: message4k,
        key: aesKey,
        nonce: nonce,
        aad: aad,
      );
    },
    justCryptoIsolate: () => crypto.encryptMessageIsolate(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: message4k,
      key: aesKey,
      nonce: nonce,
      aad: aad,
    ),
    pureDart: () {
      pureAes.encryptSync(
        message4k,
        secretKeyData: pureAesKey,
        nonce: nonce,
        aad: aad,
      );
    },
  );

  await _printSyncComparison(
    name: 'AES-256-GCM decrypt',
    payload: '4 KiB',
    syncIterations: 300,
    isolateIterations: 40,
    justCryptoSync: () {
      crypto.decryptMessage(
        algorithm: JustCryptoAlgorithm.aes256Gcm,
        message: aesCipherJust,
        key: aesKey,
        nonce: nonce,
        aad: aad,
      );
    },
    justCryptoIsolate: () => crypto.decryptMessageIsolate(
      algorithm: JustCryptoAlgorithm.aes256Gcm,
      message: aesCipherJust,
      key: aesKey,
      nonce: nonce,
      aad: aad,
    ),
    pureDart: () {
      pureAes.decryptSync(aesCipherPure, secretKeyData: pureAesKey, aad: aad);
    },
  );

  await _printSyncComparison(
    name: 'ChaCha20-Poly1305 encrypt',
    payload: '4 KiB',
    syncIterations: 300,
    isolateIterations: 40,
    justCryptoSync: () {
      crypto.encryptMessage(
        algorithm: JustCryptoAlgorithm.chacha20Poly1305,
        message: message4k,
        key: chachaKey,
        nonce: nonce,
        aad: aad,
      );
    },
    justCryptoIsolate: () => crypto.encryptMessageIsolate(
      algorithm: JustCryptoAlgorithm.chacha20Poly1305,
      message: message4k,
      key: chachaKey,
      nonce: nonce,
      aad: aad,
    ),
    pureDart: () {
      pureChacha.encryptSync(
        message4k,
        secretKey: pureChachaKey,
        nonce: nonce,
        aad: aad,
      );
    },
  );

  await _printSyncComparison(
    name: 'ChaCha20-Poly1305 decrypt',
    payload: '4 KiB',
    syncIterations: 300,
    isolateIterations: 40,
    justCryptoSync: () {
      crypto.decryptMessage(
        algorithm: JustCryptoAlgorithm.chacha20Poly1305,
        message: chachaCipherJust,
        key: chachaKey,
        nonce: nonce,
        aad: aad,
      );
    },
    justCryptoIsolate: () => crypto.decryptMessageIsolate(
      algorithm: JustCryptoAlgorithm.chacha20Poly1305,
      message: chachaCipherJust,
      key: chachaKey,
      nonce: nonce,
      aad: aad,
    ),
    pureDart: () {
      pureChacha.decryptSync(
        chachaCipherPure,
        secretKey: pureChachaKey,
        aad: aad,
      );
    },
  );

  await _printSyncComparison(
    name: 'SHA-256 hash',
    payload: '64 KiB',
    syncIterations: 800,
    isolateIterations: null,
    justCryptoSync: () {
      crypto.hashMessage(
        algorithm: JustCryptoAlgorithm.sha256,
        message: message64k,
      );
    },
    justCryptoIsolate: null,
    pureDart: () {
      pureSha256.hashSync(message64k);
    },
  );

  await _printSyncComparison(
    name: 'HMAC-SHA256',
    payload: '64 KiB',
    syncIterations: 600,
    isolateIterations: null,
    justCryptoSync: () {
      crypto.hmacMessage(
        algorithm: JustCryptoAlgorithm.hmacSha256,
        message: message64k,
        key: hmacKey,
      );
    },
    justCryptoIsolate: null,
    pureDart: () {
      pureHmac.calculateMacSync(
        message64k,
        secretKeyData: reference.SecretKeyData(hmacKey),
        nonce: const <int>[],
      );
    },
  );

  await _printAsyncComparison(
    name: 'Ed25519 sign',
    payload: '34 B',
    asyncIterations: 120,
    isolateIterations: 25,
    justCryptoSync: () async {
      crypto.signMessage(
        algorithm: JustCryptoAlgorithm.ed25519,
        message: signatureMessage,
        privateKey: justEd25519Pair.privateKey,
      );
    },
    justCryptoIsolate: () => crypto.signMessageIsolate(
      algorithm: JustCryptoAlgorithm.ed25519,
      message: signatureMessage,
      privateKey: justEd25519Pair.privateKey,
    ),
    pureDart: () =>
        pureEd25519.sign(signatureMessage, keyPair: pureEd25519KeyPair),
  );

  await _printAsyncComparison(
    name: 'Ed25519 verify',
    payload: '34 B',
    asyncIterations: 120,
    isolateIterations: 25,
    justCryptoSync: () async {
      crypto.verifyMessage(
        algorithm: JustCryptoAlgorithm.ed25519,
        message: signatureMessage,
        signature: justSignature,
        publicKey: justEd25519Pair.publicKey,
      );
    },
    justCryptoIsolate: () => crypto.verifyMessageIsolate(
      algorithm: JustCryptoAlgorithm.ed25519,
      message: signatureMessage,
      signature: justSignature,
      publicKey: justEd25519Pair.publicKey,
    ),
    pureDart: () => pureEd25519.verify(
      signatureMessage,
      signature: reference.Signature(
        pureSignBenchmarkSignature.bytes,
        publicKey: pureEd25519PublicKey,
      ),
    ),
  );

  final justArgonMicroseconds = await _measureAsyncAverage(
    iterations: 8,
    warmup: 1,
    action: () async {
      crypto.deriveKey(
        algorithm: JustCryptoAlgorithm.argon2id,
        input: password,
        salt: salt,
        memoryCost: 16 * 1024,
        timeCost: 2,
        parallelism: 1,
        outputLength: 32,
      );
    },
  );
  final justArgonIsolateMicroseconds = await _measureAsyncAverage(
    iterations: 4,
    warmup: 1,
    action: () => crypto.deriveKeyIsolate(
      algorithm: JustCryptoAlgorithm.argon2id,
      input: password,
      salt: salt,
      memoryCost: 16 * 1024,
      timeCost: 2,
      parallelism: 1,
      outputLength: 32,
    ),
  );
  print(
    '| Argon2id derive | 16 MiB / t=2 | ${_formatMicros(justArgonMicroseconds)} | ${_formatMicros(justArgonIsolateMicroseconds)} | n/a | n/a |',
  );

  print('');
  print('Notes:');
  print(
    '- Argon2id, BLAKE3, CBC y X25519 no se comparan aquí con pure Dart porque no hay una referencia equivalente clara y puramente Dart para esta API exacta dentro del benchmark.',
  );
  print('- Las columnas isolate miden coste total de ida y vuelta al isolate.');
  print(
    '- just_crypto usa Rust FFI vía Dart Hooks; la referencia usa package:cryptography/dart.dart.',
  );
  print('');
  print('Argon2id sample digest: ${_hex(justArgon)}');
  print(
    'Ed25519 reference public key from just_crypto seed: ${_hex(referenceKeyPairFromJustPublic.bytes)}',
  );
}

Future<void> _printSyncComparison({
  required String name,
  required String payload,
  required int syncIterations,
  required int? isolateIterations,
  required void Function() justCryptoSync,
  required Future<void> Function()? justCryptoIsolate,
  required void Function() pureDart,
}) async {
  final justCryptoMicros = _measureSyncAverage(
    iterations: syncIterations,
    warmup: 5,
    action: justCryptoSync,
  );
  final justCryptoIsolateMicros =
      justCryptoIsolate == null || isolateIterations == null
      ? null
      : await _measureAsyncAverage(
          iterations: isolateIterations,
          warmup: 2,
          action: justCryptoIsolate,
        );
  final pureDartMicros = _measureSyncAverage(
    iterations: syncIterations,
    warmup: 5,
    action: pureDart,
  );
  final speedup = pureDartMicros / justCryptoMicros;
  print(
    '| $name | $payload | ${_formatMicros(justCryptoMicros)} | ${justCryptoIsolateMicros == null ? 'n/a' : _formatMicros(justCryptoIsolateMicros)} | ${_formatMicros(pureDartMicros)} | ${speedup.toStringAsFixed(2)}x |',
  );
}

Future<void> _printAsyncComparison({
  required String name,
  required String payload,
  required int asyncIterations,
  required int isolateIterations,
  required Future<void> Function() justCryptoSync,
  required Future<void> Function() justCryptoIsolate,
  required Future<void> Function() pureDart,
}) async {
  final justCryptoMicros = await _measureAsyncAverage(
    iterations: asyncIterations,
    warmup: 3,
    action: justCryptoSync,
  );
  final justCryptoIsolateMicros = await _measureAsyncAverage(
    iterations: isolateIterations,
    warmup: 2,
    action: justCryptoIsolate,
  );
  final pureDartMicros = await _measureAsyncAverage(
    iterations: asyncIterations,
    warmup: 3,
    action: pureDart,
  );
  final speedup = pureDartMicros / justCryptoMicros;
  print(
    '| $name | $payload | ${_formatMicros(justCryptoMicros)} | ${_formatMicros(justCryptoIsolateMicros)} | ${_formatMicros(pureDartMicros)} | ${speedup.toStringAsFixed(2)}x |',
  );
}

double _measureSyncAverage({
  required int iterations,
  required int warmup,
  required void Function() action,
}) {
  for (var index = 0; index < warmup; index++) {
    action();
  }
  final stopwatch = Stopwatch()..start();
  for (var index = 0; index < iterations; index++) {
    action();
  }
  stopwatch.stop();
  return stopwatch.elapsedMicroseconds / iterations;
}

Future<double> _measureAsyncAverage({
  required int iterations,
  required int warmup,
  required Future<void> Function() action,
}) async {
  for (var index = 0; index < warmup; index++) {
    await action();
  }
  final stopwatch = Stopwatch()..start();
  for (var index = 0; index < iterations; index++) {
    await action();
  }
  stopwatch.stop();
  return stopwatch.elapsedMicroseconds / iterations;
}

Uint8List _bytes(int length, int seed) {
  return Uint8List.fromList(
    List<int>.generate(length, (index) => (seed + index * 31) & 0xff),
  );
}

void _expectEqual(String label, List<int> left, List<int> right) {
  if (!_listEquals(left, right)) {
    throw StateError('$label mismatch');
  }
}

bool _listEquals(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

String _formatMicros(double micros) =>
    '${(micros / 1000).toStringAsFixed(3)} ms';

String _hex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final byte in bytes) {
    buffer.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}
