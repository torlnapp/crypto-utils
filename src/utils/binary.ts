import type { Binary } from '../types/array';

export function toArrayBuffer(buffer: ArrayBufferLike): ArrayBuffer {
  if (buffer instanceof ArrayBuffer) {
    return buffer;
  }

  return new Uint8Array(buffer).slice().buffer;
}

export function toBinary(data: unknown): Binary {
  if (data instanceof Uint8Array) {
    return new Uint8Array(toArrayBuffer(data.buffer));
  } else if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  } else {
    throw new TypeError('Data is not in a binary format.');
  }
}

export function isBinary(data: unknown): data is Binary {
  return data instanceof Uint8Array || data instanceof ArrayBuffer;
}
