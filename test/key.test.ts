import { describe, expect, it } from 'bun:test';

import {
  exportKeyToJwk,
  exportKeyToRaw,
  generateAESGCMKey,
  generateEd25519KeyPair,
  generateHKDFKey,
  generateX25519KeyPair,
  importKey,
  isCryptoKey,
  isCryptoKeyPair,
  isJsonWebKey,
} from '../src/crypto/key';

describe('key helpers', () => {
  it('generates an Ed25519 key pair with correct usages', async () => {
    const pair = await generateEd25519KeyPair();
    expect(isCryptoKeyPair(pair)).toBe(true);
    expect(pair.publicKey.algorithm.name).toBe('Ed25519');
    expect(pair.publicKey.usages).toEqual(['verify']);
    expect(pair.privateKey.usages).toEqual(['sign']);
  });

  it('creates a 256-bit AES-GCM key', async () => {
    const key = await generateAESGCMKey();
    expect(isCryptoKey(key)).toBe(true);
    expect(key.algorithm.name).toBe('AES-GCM');
    const { length } = key.algorithm as { length?: number };
    expect(length).toBe(256);
    expect(key.usages).toContain('encrypt');
    expect(key.usages).toContain('decrypt');
  });

  it('imports HKDF seed material', async () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const key = await generateHKDFKey(seed);
    expect(key.algorithm.name).toBe('HKDF');
    expect(key.usages).toContain('deriveKey');
    expect(key.usages).toContain('deriveBits');
  });

  it('creates an X25519 key pair for key agreement', async () => {
    const pair = await generateX25519KeyPair();
    expect(isCryptoKeyPair(pair)).toBe(true);
    expect(pair.publicKey.algorithm.name).toBe('X25519');
    expect(pair.publicKey.type).toBe('public');
    expect(pair.privateKey.type).toBe('private');
  });

  it('exports and re-imports AES keys', async () => {
    const key = await generateAESGCMKey();
    const jwk = await exportKeyToJwk(key);
    expect(isJsonWebKey(jwk)).toBe(true);
    expect('kty' in jwk).toBe(true);

    const imported = await importKey(jwk, { name: 'AES-GCM' }, [
      'encrypt',
      'decrypt',
    ]);
    expect(isCryptoKey(imported)).toBe(true);
    expect(imported.algorithm.name).toBe('AES-GCM');

    const raw = await exportKeyToRaw(imported);
    expect(raw.length).toBe(32); // 256 bits
  });
});
