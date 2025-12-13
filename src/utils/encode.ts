import { encode } from '@msgpack/msgpack';
import type { Binary } from '../types/array';

export async function encodeBase64(data: Binary): Promise<string> {
  const uint8Array = new Uint8Array(data);
  const binary = Array.from(uint8Array, (byte) =>
    String.fromCharCode(byte),
  ).join('');
  return btoa(binary);
}

export function encodeMsgPack(data: unknown): Binary {
  const encodedData = new Uint8Array(encode(data));
  return encodedData;
}

export function encodeUTF8(data: string): Binary {
  const encoder = new TextEncoder();
  return encoder.encode(data);
}
