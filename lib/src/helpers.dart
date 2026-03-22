import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'bindings.dart';
import 'errors.dart';

/// Temporarily allocates FFI memory for a [Uint8List], runs the [action],
/// and then immediately frees the memory safely.
T withPointer<T>(
  Uint8List? data,
  T Function(Pointer<Uint8> ptr, int len) action,
) {
  if (data == null || data.isEmpty) {
    return action(nullptr, 0);
  }

  final Pointer<Uint8> ptr = calloc<Uint8>(data.length);
  try {
    final Uint8List nativeList = ptr.asTypedList(data.length);
    nativeList.setAll(0, data);
    return action(ptr, data.length);
  } finally {
    ptr.asTypedList(data.length).fillRange(0, data.length, 0);
    calloc.free(ptr);
  }
}

/// Takes a native [JCResult] from rust, validates its success, and copies it to a Dart [Uint8List].
/// Also frees the backing memory buffer on the Rust side to prevent memory leaks.
Uint8List parseAndFreeResult(JCResult result) {
  try {
    throwOnFailure(result.code);

    if (result.buffer.ptr == nullptr || result.buffer.len == 0) {
      return Uint8List(0);
    }

    // Copy data from Rust memory to Dart managed memory
    final data = result.buffer.ptr.asTypedList(result.buffer.len);
    final copy = Uint8List.fromList(data);
    return copy;
  } finally {
    // ALWAYS instruct Rust to free its allocated buffer
    jcBufferFree(result.buffer);
  }
}
