import type { Binary } from '../types/array';

export function toArrayBuffer(buffer: ArrayBufferLike): ArrayBuffer {
  if (buffer instanceof ArrayBuffer) {
    return buffer;
  }

  return new Uint8Array(buffer).slice().buffer;
}

export function toBinary(data: unknown): Binary {
  if (data instanceof Uint8Array) {
    const tightArray = toTightUint8Array(data);
    return new Uint8Array(toArrayBuffer(tightArray.buffer));
  } else if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  } else {
    throw new TypeError('Data is not in a binary format.');
  }
}

export function isBinary(data: unknown): data is Binary {
  return data instanceof Uint8Array || data instanceof ArrayBuffer;
}

export function toTightUint8Arrays(data: unknown) {
  if (!data || !isProcessableObject(data)) {
    return data;
  }

  if (isUint8Array(data)) {
    return toTightUint8Array(data);
  }

  for (const key in data) {
    if (!isObjectKey(key, data)) {
      continue;
    }

    const prop = data[key];
    if (isUint8Array(prop)) {
      data[key] = toTightUint8Array(prop);
    } else if (isProcessableObject(prop)) {
      data[key] = toTightUint8Arrays(prop);
    }
  }

  return data;
}

export function toTightUint8Array(array: Uint8Array): Uint8Array {
  if (array.byteOffset === 0 && array.byteLength === array.buffer.byteLength) {
    return array;
  }

  return array.slice();
}

function isObjectKey(
  key: string,
  obj: Record<string, unknown>,
): key is keyof typeof obj {
  return Object.hasOwn(obj, key);
}

function isProcessableObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isUint8Array(value: unknown): value is Uint8Array<ArrayBuffer> {
  return value instanceof Uint8Array;
}
