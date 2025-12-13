import { decode } from '@msgpack/msgpack';
import type { Binary } from '../types/array';

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

export function decodeMsgPack(data: Binary): unknown {
  return decode(data);
}

export function decodeUtf8(data: Binary): string {
  const decoder = new TextDecoder();
  return decoder.decode(data);
}
