import { describe, expect, test } from 'bun:test';

import {
  AES,
  cm,
  decodeBase64,
  decodeMsgPack,
  decodeUtf8,
  Ed25519,
  encodeBase64,
  encodeMsgPack,
  encodeUTF8,
  generateNonce,
  HKDF,
  processCiphertext,
  SHA256,
  X25519,
} from '../src/index.ts';

const toHex = (data: Uint8Array) =>
  Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');

describe('encoding utilities', () => {
  test('base64 round-trip', () => {
    const text = 'hello world';
    const binary = encodeUTF8(text);

    const encoded = encodeBase64(binary);
    expect(encoded).toBe('aGVsbG8gd29ybGQ=');

    const decoded = decodeBase64(encodeUTF8(encoded));
    expect(decoded).toBe(text);
  });

  test('msgpack encode/decode is stable', () => {
    const payload = { b: 2, a: 1 };

    const packed = encodeMsgPack(payload);
    const unpacked = decodeMsgPack(packed);
    expect(unpacked).toEqual(payload);
  });

  test('canonicalized msgpack matches deterministic JSON', () => {
    const payload = { z: true, a: 1 };

    const packed = cm(payload);
    const decoded = decodeMsgPack(packed);

    expect(decoded).toBe('{"a":1,"z":true}');
  });
});

describe('crypto helpers', () => {
  test('generateNonce returns 96-bit nonce', () => {
    const nonce = generateNonce();
    expect(nonce).toHaveLength(12);
  });

  test('processCiphertext splits ciphertext and tag', async () => {
    const key = await AES.generateKey();
    const plaintext = encodeUTF8('split me');

    const encrypted = await AES.encrypt(plaintext, key);
    const { ciphertext, tag } = processCiphertext(encrypted.slice(12));

    expect(tag).toHaveLength(16);
    expect(ciphertext.length + tag.length).toBe(encrypted.length - 12);
  });
});

describe('algorithms', () => {
  test('AES encrypt/decrypt round-trip', async () => {
    const key = await AES.generateKey();
    const plaintext = encodeUTF8('secret message');

    const encrypted = await AES.encrypt(plaintext, key);
    const decrypted = await AES.decrypt(encrypted, key);

    expect(decodeUtf8(decrypted)).toBe('secret message');
  });

  test('HKDF derived keys are consistent', async () => {
    const seedKey = await HKDF.generateKey();
    const salt = encodeUTF8('salt');
    const info = encodeUTF8('info');

    const derivedA = await HKDF.deriveKey(seedKey, salt, info);
    const derivedB = await HKDF.deriveKey(seedKey, salt, info);

    const payload = encodeUTF8('derived data');
    const encrypted = await AES.encrypt(payload, derivedA);
    const decrypted = await AES.decrypt(encrypted, derivedB);

    expect(decodeUtf8(decrypted)).toBe('derived data');

    const bits = await HKDF.deriveBits(seedKey, salt, info);
    expect(bits).toHaveLength(32);
  });

  test('Ed25519 signatures verify and reject tampering', async () => {
    const { privateKey, publicKey } = await Ed25519.generateKeyPair();
    const message = encodeUTF8('signed data');

    const signature = await Ed25519.sign(message, privateKey);
    expect(await Ed25519.verify(message, signature, publicKey)).toBe(true);

    const tampered = new Uint8Array(signature);
    const firstByte = tampered.at(0);
    if (firstByte === undefined) {
      throw new Error('Signature unexpectedly empty');
    }
    tampered[0] = firstByte ^ 0xff;
    expect(await Ed25519.verify(message, tampered, publicKey)).toBe(false);
  });

  // X25519 support in Bun is not yet complete
  // https://github.com/oven-sh/bun/issues/20148
  test.skip('X25519 shared secret matches for both parties', async () => {
    const alice = await X25519.generateKeyPair();
    const bob = await X25519.generateKeyPair();

    const secretA = await X25519.deriveSecret(alice.privateKey, bob.publicKey);
    const secretB = await X25519.deriveSecret(bob.privateKey, alice.publicKey);

    expect(toHex(secretA)).toBe(toHex(secretB));
  });

  test('SHA256 matches known test vector', async () => {
    const digest = await SHA256.hash('abc');
    expect(toHex(digest)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
