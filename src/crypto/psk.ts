import { generateHKDFKey } from './key';

export function generateRandomPskBytes(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function derivePskBytes(
  pskBytes: Uint8Array<ArrayBuffer>,
  salt: string,
  info: string,
): Promise<Uint8Array<ArrayBuffer>> {
  const hkdfBase = await generateHKDFKey(pskBytes);
  const infoBuffer = new TextEncoder().encode(info);

  const saltHashBuffer = await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(salt),
  );
  const derivedBits = await globalThis.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltHashBuffer,
      info: infoBuffer,
    },
    hkdfBase,
    256,
  );

  return new Uint8Array(derivedBits);
}
