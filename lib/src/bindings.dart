// ignore_for_file: non_constant_identifier_names

import 'dart:ffi' as ffi;

final class JCBuffer extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> ptr;

  @ffi.IntPtr()
  external int len;
}

final class JCResult extends ffi.Struct {
  @ffi.Int32()
  external int code;

  external JCBuffer buffer;
}

@ffi.Native<ffi.Void Function(JCBuffer)>(symbol: 'jc_buffer_free')
external void jcBufferFree(JCBuffer buffer);

@ffi.Native<
  JCResult Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_encrypt')
external JCResult jcEncrypt(
  int alg,
  ffi.Pointer<ffi.Uint8> messagePtr,
  int messageLen,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
  ffi.Pointer<ffi.Uint8> noncePtr,
  int nonceLen,
  ffi.Pointer<ffi.Uint8> aadPtr,
  int aadLen,
);

@ffi.Native<
  JCResult Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_decrypt')
external JCResult jcDecrypt(
  int alg,
  ffi.Pointer<ffi.Uint8> messagePtr,
  int messageLen,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
  ffi.Pointer<ffi.Uint8> noncePtr,
  int nonceLen,
  ffi.Pointer<ffi.Uint8> aadPtr,
  int aadLen,
);

@ffi.Native<
  JCResult Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_sign')
external JCResult jcSign(
  int alg,
  ffi.Pointer<ffi.Uint8> messagePtr,
  int messageLen,
  ffi.Pointer<ffi.Uint8> privateKeyPtr,
  int privateKeyLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_verify')
external int jcVerify(
  int alg,
  ffi.Pointer<ffi.Uint8> messagePtr,
  int messageLen,
  ffi.Pointer<ffi.Uint8> signaturePtr,
  int signatureLen,
  ffi.Pointer<ffi.Uint8> publicKeyPtr,
  int publicKeyLen,
);

@ffi.Native<
  JCResult Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Uint32,
    ffi.Uint32,
    ffi.Uint32,
    ffi.Uint32,
  )
>(symbol: 'jc_derive_key')
external JCResult jcDeriveKey(
  int alg,
  ffi.Pointer<ffi.Uint8> inputPtr,
  int inputLen,
  ffi.Pointer<ffi.Uint8> saltPtr,
  int saltLen,
  int memoryCost,
  int timeCost,
  int parallelism,
  int outputLength,
);

@ffi.Native<JCResult Function(ffi.IntPtr)>(symbol: 'jc_generate_random')
external JCResult jcGenerateRandom(int length);

@ffi.Native<JCResult Function(ffi.Int32)>(symbol: 'jc_generate_key_pair')
external JCResult jcGenerateKeyPair(int alg);

@ffi.Native<
  JCResult Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_shared_secret')
external JCResult jcSharedSecret(
  int alg,
  ffi.Pointer<ffi.Uint8> privateKeyPtr,
  int privateKeyLen,
  ffi.Pointer<ffi.Uint8> publicKeyPtr,
  int publicKeyLen,
);

@ffi.Native<JCResult Function(ffi.Int32, ffi.Pointer<ffi.Uint8>, ffi.IntPtr)>(
  symbol: 'jc_hash_message',
)
external JCResult jcHashMessage(
  int alg,
  ffi.Pointer<ffi.Uint8> messagePtr,
  int messageLen,
);

@ffi.Native<
  JCResult Function(
    ffi.Int32,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_hmac_message')
external JCResult jcHmacMessage(
  int alg,
  ffi.Pointer<ffi.Uint8> messagePtr,
  int messageLen,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
);

@ffi.Native<ffi.Pointer<ffi.Void> Function(ffi.Int32)>(
  symbol: 'jc_stream_init_hash',
)
external ffi.Pointer<ffi.Void> jcStreamInitHash(int alg);

@ffi.Native<
  ffi.Pointer<ffi.Void> Function(ffi.Int32, ffi.Pointer<ffi.Uint8>, ffi.IntPtr)
>(symbol: 'jc_stream_init_hmac')
external ffi.Pointer<ffi.Void> jcStreamInitHmac(
  int alg,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
);

@ffi.Native<
  ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, ffi.IntPtr)
>(symbol: 'jc_stream_update')
external int jcStreamUpdate(
  ffi.Pointer<ffi.Void> context,
  ffi.Pointer<ffi.Uint8> dataPtr,
  int dataLen,
);

@ffi.Native<JCResult Function(ffi.Pointer<ffi.Void>)>(
  symbol: 'jc_stream_finalize',
)
external JCResult jcStreamFinalize(ffi.Pointer<ffi.Void> context);

@ffi.Native<ffi.Void Function(ffi.Pointer<ffi.Void>)>(symbol: 'jc_stream_free')
external void jcStreamFree(ffi.Pointer<ffi.Void> context);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
    ffi.Pointer<ffi.Uint8>,
    ffi.IntPtr,
  )
>(symbol: 'jc_constant_time_eq')
external int jcConstantTimeEq(
  ffi.Pointer<ffi.Uint8> leftPtr,
  int leftLen,
  ffi.Pointer<ffi.Uint8> rightPtr,
  int rightLen,
);
