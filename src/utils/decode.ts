import { decode } from '@msgpack/msgpack';
import type { Binary } from '../types/array';
import { toTightUint8Arrays } from './binary';

export function decodeBase64(data: Binary): string {
  if (!('atob' in globalThis)) {
    throw new Error('Base64 decoding is not supported in this environment.');
  }

  const uint8Array = new Uint8Array(data);
  const binary = Array.from(uint8Array, (byte) =>
    String.fromCharCode(byte),
  ).join('');
  return globalThis.atob(binary);
}

export function decodeMsgPack<T extends object>(data: Binary): T {
  return toTightUint8Arrays(decode(data)) as T;
}

export function decodeUTF8(data: Binary): string {
  const decoder = new TextDecoder();
  return decoder.decode(data);
}
