import type { webcrypto } from 'node:crypto';

export async function encrypt(
  algorithm: webcrypto.AlgorithmIdentifier,
  key: webcrypto.CryptoKey,
  data: Uint8Array<ArrayBuffer> | string,
): Promise<Uint8Array<ArrayBuffer>> {
  const buffer = new Uint8Array(
    typeof data === 'string' ? new TextEncoder().encode(data) : data,
  );
  const encrypted = await globalThis.crypto.subtle.encrypt(
    algorithm === 'AES-GCM'
      ? {
          name: 'AES-GCM',
          iv: globalThis.crypto.getRandomValues(new Uint8Array(12)),
        }
      : algorithm,
    key,
    buffer,
  );
  return new Uint8Array(encrypted);
}
