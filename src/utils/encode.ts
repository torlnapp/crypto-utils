import { encode } from '@msgpack/msgpack';
import type { Binary } from '../types/array';

export function encodeBase64(data: Binary): string {
  if (!('btoa' in globalThis)) {
    throw new Error('Base64 encoding is not supported in this environment.');
  }

  const uint8Array = new Uint8Array(data);
  const binary = Array.from(uint8Array, (byte) =>
    String.fromCharCode(byte),
  ).join('');
  return globalThis.btoa(binary);
}

export function encodeMsgPack<T>(data: T): Binary {
  const encodedData = new Uint8Array(encode(data));
  return encodedData;
}

export function encodeUTF8(data: string): Binary {
  const encoder = new TextEncoder();
  return encoder.encode(data);
}
