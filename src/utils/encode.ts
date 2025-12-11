import { decode, encode } from '@msgpack/msgpack';

export async function base64(data: Uint8Array): Promise<string> {
  const uint8Array = new Uint8Array(data);
  const binary = Array.from(uint8Array, (byte) =>
    String.fromCharCode(byte),
  ).join('');
  return btoa(binary);
}

export function encodeMsgPack(data: unknown): Uint8Array<ArrayBuffer> {
  const encodedData = new Uint8Array(encode(data));
  return encodedData;
}

export function decodeMsgPack(data: Uint8Array): unknown {
  return decode(data);
}
