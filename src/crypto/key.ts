import type { webcrypto } from 'node:crypto';

export async function generateEd25519KeyPair(): Promise<webcrypto.CryptoKeyPair> {
  const result = await crypto.subtle.generateKey(
    {
      name: 'Ed25519',
    },
    true,
    ['sign', 'verify'],
  );

  if (isCryptoKeyPair(result)) {
    return result;
  }

  throw new Error('Ed25519 Key pair generation failed');
}

export function generateAESGCMKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

export function generateHKDFKey(
  seed: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', seed, { name: 'HKDF' }, false, [
    'deriveKey',
    'deriveBits',
  ]);
}

export async function generateX25519KeyPair(): Promise<CryptoKeyPair> {
  const keypair = await crypto.subtle.generateKey(
    {
      name: 'X25519',
    },
    true,
    ['deriveKey', 'deriveBits'],
  );

  if (isCryptoKeyPair(keypair)) {
    return keypair;
  }

  throw new Error('X25519 Key pair generation failed');
}

export function importKey(
  jwk: webcrypto.JsonWebKey,
  algorithm: webcrypto.Algorithm,
  usages: Array<webcrypto.KeyUsage>,
): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, algorithm, true, usages);
}

export function importPsk(psk: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', psk, 'HKDF', false, ['deriveBits']);
}

export function exportKeyToJwk(key: CryptoKey): Promise<webcrypto.JsonWebKey> {
  return crypto.subtle.exportKey('jwk', key);
}

export async function exportKeyToRaw(
  key: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> {
  const buffer = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(buffer);
}

export function isJsonWebKey(key: unknown): key is webcrypto.JsonWebKey {
  return typeof key === 'object' && key !== null && 'kty' in key;
}

export function isCryptoKey(key: unknown): key is webcrypto.CryptoKey {
  return key instanceof CryptoKey;
}

export function isCryptoKeyPair(
  keypair: unknown,
): keypair is webcrypto.CryptoKeyPair {
  return (
    typeof keypair === 'object' &&
    keypair !== null &&
    'publicKey' in keypair &&
    'privateKey' in keypair &&
    isCryptoKey(keypair.publicKey) &&
    isCryptoKey(keypair.privateKey)
  );
}
