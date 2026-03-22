/// Represents an error coming from the just_crypto native backend.
class JustCryptoException implements Exception {
  final int code;
  final String message;

  const JustCryptoException(this.code, this.message);

  @override
  String toString() => 'JustCryptoException (Code: $code): $message';
}

class JustCryptoErrorCodes {
  static const int success = 0;
  static const int invalidParam = -1;
  static const int invalidKeySize = -2;
  static const int invalidNonceSize = -3;
  static const int decryptionFailed = -4;
  static const int allocationFailed = -5;
  static const int unsupportedAlgo = -6;
  static const int invalidSignature = -7;
  static const int invalidPointer = -8;
  static const int invalidState = -9;
  static const int invalidIvSize = -10;
  static const int invalidSaltSize = -11;
  static const int unknown = -99;
}

void throwOnFailure(int code) {
  if (code == JustCryptoErrorCodes.success) return;
  switch (code) {
    case JustCryptoErrorCodes.invalidParam:
      throw const JustCryptoException(
        -1,
        'Invalid parameter provided to native function.',
      );
    case JustCryptoErrorCodes.invalidKeySize:
      throw const JustCryptoException(-2, 'Invalid key size provided.');
    case JustCryptoErrorCodes.invalidNonceSize:
      throw const JustCryptoException(-3, 'Invalid nonce size provided.');
    case JustCryptoErrorCodes.decryptionFailed:
      throw const JustCryptoException(-4, 'Decryption/authentication failed.');
    case JustCryptoErrorCodes.allocationFailed:
      throw const JustCryptoException(
        -5,
        'Memory allocation failed in native backend.',
      );
    case JustCryptoErrorCodes.unsupportedAlgo:
      throw const JustCryptoException(
        -6,
        'Algorithm explicitly unsupported by this operation.',
      );
    case JustCryptoErrorCodes.invalidSignature:
      throw const JustCryptoException(-7, 'Invalid signature provided.');
    case JustCryptoErrorCodes.invalidPointer:
      throw const JustCryptoException(
        -8,
        'Native pointer/length pair is invalid.',
      );
    case JustCryptoErrorCodes.invalidState:
      throw const JustCryptoException(
        -9,
        'Operation used an invalid native state.',
      );
    case JustCryptoErrorCodes.invalidIvSize:
      throw const JustCryptoException(-10, 'Invalid IV size provided.');
    case JustCryptoErrorCodes.invalidSaltSize:
      throw const JustCryptoException(-11, 'Invalid salt size provided.');
    default:
      throw JustCryptoException(
        code,
        'Unknown native cryptographic error ($code).',
      );
  }
}
