import { describe, expect, test } from 'bun:test';

import {
  AES,
  asKeyPair,
  asPrivateKey,
  asPublicKey,
  asSymmetricKey,
  cm,
  decodeBase64,
  decodeMsgPack,
  decodeUTF8,
  Ed25519,
  encodeBase64,
  encodeMsgPack,
  encodeUTF8,
  generateNonce,
  getAlgorithmIdentifier,
  HKDF,
  importKey,
  isBinary,
  isJWK,
  processCiphertext,
  SHA256,
  toArrayBuffer,
  toBinary,
  toTightUint8Array,
  toTightUint8Arrays,
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

  test('encodeBase64 throws when btoa is missing', () => {
    const original = globalThis.btoa;

    // @ts-expect-error - delete for testing
    delete globalThis.btoa;

    expect(() => encodeBase64(encodeUTF8('hi'))).toThrow();

    globalThis.btoa = original;
  });

  test('decodeBase64 throws when atob is missing', () => {
    const original = globalThis.atob;

    // @ts-expect-error - delete for testing
    delete globalThis.atob;

    expect(() => decodeBase64(encodeUTF8('aGVsbG8='))).toThrow();

    globalThis.atob = original;
  });

  test('cm throws when canonicalization fails', () => {
    expect(() => cm(() => {})).toThrow('Failed to canonicalize payload');
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

    const encrypted = await AES.encrypt(key, plaintext);
    const { ciphertext, tag } = processCiphertext(encrypted.slice(12));

    expect(tag).toHaveLength(16);
    expect(ciphertext.length + tag.length).toBe(encrypted.length - 12);
  });

  test('toTightUint8Array compacts sliced views', () => {
    const buffer = new Uint8Array([0, 1, 2, 3, 4, 5]).buffer;
    const view = new Uint8Array(buffer, 2, 3);

    const compact = toTightUint8Array(view);

    expect(compact.byteOffset).toBe(0);
    expect(Array.from(compact)).toEqual([2, 3, 4]);
  });

  test('toTightUint8Arrays walks nested objects', () => {
    const buffer = new Uint8Array([9, 8, 7, 6]).buffer;
    const nested = { inner: { data: new Uint8Array(buffer, 1, 2) } };

    const result = toTightUint8Arrays(nested) as typeof nested;

    expect(result.inner.data.byteOffset).toBe(0);
    expect(Array.from(result.inner.data)).toEqual([8, 7]);
  });

  test('toTightUint8Arrays leaves non-objects untouched', () => {
    expect(toTightUint8Arrays(42)).toBe(42);
  });

  test('toTightUint8Arrays returns original for already tight array', () => {
    const arr = new Uint8Array([1, 2, 3]);
    expect(toTightUint8Arrays(arr)).toBe(arr);
  });

  test('toArrayBuffer handles ArrayBuffer and ArrayBufferView', () => {
    const view = new Uint8Array([1, 2, 3]);
    const bufferFromArray = toArrayBuffer(view.buffer);
    expect(bufferFromArray).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(bufferFromArray)).toEqual(view);

    const slicedView = view.subarray(1); // triggers copy path
    const bufferFromView = toArrayBuffer(
      slicedView as unknown as ArrayBufferLike,
    );
    expect(bufferFromView).toBeInstanceOf(ArrayBuffer);
    expect(new Uint8Array(bufferFromView)).toEqual(slicedView);
  });

  test('toBinary handles ArrayBuffer and errors on invalid input', () => {
    const buffer = new Uint8Array([4, 5]).buffer;
    expect(toBinary(buffer)).toBeInstanceOf(Uint8Array);
    expect(() => toBinary('oops')).toThrow('Data is not in a binary format.');
  });

  test('toBinary copies Uint8Array views', () => {
    const view = new Uint8Array([6, 7, 8]);
    const copy = toBinary(view);

    expect(copy).not.toBe(view);
    expect(Array.from(copy)).toEqual([6, 7, 8]);
  });

  test('isBinary detects Uint8Array and ArrayBuffer', () => {
    expect(isBinary(new Uint8Array(2))).toBe(true);
    expect(isBinary(new ArrayBuffer(2))).toBe(true);
    expect(isBinary('nope')).toBe(false);
  });
});

describe('algorithms', () => {
  test('AES encrypt/decrypt round-trip', async () => {
    const key = await AES.generateKey();
    const plaintext = encodeUTF8('secret message');

    const encrypted = await AES.encrypt(key, plaintext);
    const decrypted = await AES.decrypt(key, encrypted);

    expect(decodeUTF8(decrypted)).toBe('secret message');
  });

  test('AES export/import raw and JWK', async () => {
    const key = await AES.generateKey();
    const raw = await AES.exportKeyToRaw(key);
    const jwk = await AES.exportKeyToJWK(key);

    const fromRaw = await AES.importKey(raw);
    const fromJwk = await AES.importKey(jwk);

    const plaintext = encodeUTF8('roundtrip');
    const cipher = await AES.encrypt(fromRaw, plaintext);
    const decoded = await AES.decrypt(fromJwk, cipher);
    expect(decodeUTF8(decoded)).toBe('roundtrip');
  });

  test('HKDF derived keys are consistent', async () => {
    const seedKey = await HKDF.generateKey();
    const salt = encodeUTF8('salt');
    const info = encodeUTF8('info');

    const derivedA = await HKDF.deriveKey(seedKey, salt, info);
    const derivedB = await HKDF.deriveKey(seedKey, salt, info);

    const payload = encodeUTF8('derived data');
    const encrypted = await AES.encrypt(derivedA, payload);
    const decrypted = await AES.decrypt(derivedB, encrypted);

    expect(decodeUTF8(decrypted)).toBe('derived data');

    const bits = await HKDF.deriveBits(seedKey, salt, info);
    expect(bits).toHaveLength(32);
  });

  test('HKDF import raw key supports deriveKey/deriveBits', async () => {
    const rawKey = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
    const key = await HKDF.importKey(rawKey);

    const salt = encodeUTF8('raw-salt');
    const info = encodeUTF8('raw-info');

    const aesKey = await HKDF.deriveKey(key, salt, info);
    const plaintext = encodeUTF8('raw-import');
    const cipher = await AES.encrypt(aesKey, plaintext);
    const decrypted = await AES.decrypt(aesKey, cipher);

    expect(decodeUTF8(decrypted)).toBe('raw-import');

    const bits = await HKDF.deriveBits(key, salt, info);
    expect(bits).toHaveLength(32);
  });

  test('Ed25519 signatures verify and reject tampering', async () => {
    const { privateKey, publicKey } = await Ed25519.generateKeyPair();
    const message = encodeUTF8('signed data');

    const signature = await Ed25519.sign(privateKey, message);
    expect(await Ed25519.verify(publicKey, message, signature)).toBe(true);

    const tampered = new Uint8Array(signature);
    const firstByte = tampered.at(0);
    if (firstByte === undefined) {
      throw new Error('Signature unexpectedly empty');
    }
    tampered[0] = firstByte ^ 0xff;
    expect(await Ed25519.verify(publicKey, message, tampered)).toBe(false);
  });

  // Skip X25519 import/export tests due to Bun crypto limitations
  // https://github.com/oven-sh/bun/issues/20148
  test.skip('X25519 shared secret matches for both parties when supported', async () => {
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

describe('key utilities', () => {
  test('asSymmetricKey accepts secret keys and rejects others', async () => {
    const aesKey = await AES.generateKey();
    expect(asSymmetricKey(aesKey).type).toBe('secret');

    const { publicKey } = await Ed25519.generateKeyPair();
    expect(() => asSymmetricKey(publicKey)).toThrow(
      'The provided key is not a symmetric key.',
    );
  });

  test('asPublicKey/asPrivateKey guard key types', async () => {
    const { publicKey, privateKey } = await Ed25519.generateKeyPair();
    expect(asPublicKey(publicKey).type).toBe('public');
    expect(asPrivateKey(privateKey).type).toBe('private');

    const aesKey = await AES.generateKey();
    expect(() => asPublicKey(aesKey)).toThrow(
      'The provided key is not a public key.',
    );
    expect(() => asPrivateKey(aesKey)).toThrow(
      'The provided key is not a private key.',
    );
  });

  test('asKeyPair preserves keys', async () => {
    const pair = await Ed25519.generateKeyPair();
    const shaped = asKeyPair(pair);
    expect(shaped.publicKey).toBe(pair.publicKey);
    expect(shaped.privateKey).toBe(pair.privateKey);
  });

  test('isJWK detects JWK-like objects', () => {
    expect(isJWK({ kty: 'oct' })).toBe(true);
    expect(isJWK(123)).toBe(false);
  });

  test('import/export key using raw and JWK', async () => {
    const aesKey = await AES.generateKey();
    const raw = await AES.exportKeyToRaw(aesKey);
    const jwk = await AES.exportKeyToJWK(aesKey);

    const importedRaw = await importKey(raw, 'AES-GCM', ['encrypt']);
    const importedJwk = await importKey(jwk, 'AES-GCM', ['encrypt']);

    expect(importedRaw.type).toBe('secret');
    expect(importedJwk.type).toBe('secret');

    expect(importKey(new Uint8Array(), 'AES-GCM', [])).rejects.toThrow(
      'Data provided to an operation does not meet requirements',
    );
  });

  test('Ed25519 import/export flows', async () => {
    const pair = await Ed25519.generateKeyPair();
    const publicRaw = await Ed25519.exportKeyToRaw(pair.publicKey);
    const publicImported = await Ed25519.importPublicKey(publicRaw);
    expect(publicImported.type).toBe('public');

    const privateJwk = await Ed25519.exportKeyToJWK(pair.privateKey);
    const privateImported = await Ed25519.importPrivateKey(privateJwk);
    expect(privateImported.type).toBe('private');
  });

  test('getAlgorithmIdentifier throws on unsupported algorithm', () => {
    expect(() =>
      getAlgorithmIdentifier('unknown' as unknown as 'AES-GCM'),
    ).toThrow('Unsupported algorithm: unknown');
  });

  test('getAlgorithmIdentifier returns X25519 mapping', () => {
    expect(getAlgorithmIdentifier('X25519')).toEqual({ name: 'X25519' });
  });

  // Skip X25519 import/export tests due to Bun crypto limitations
  // https://github.com/oven-sh/bun/issues/20148
  test.skip('X25519 import/export paths', async () => {
    const keyPair = await X25519.generateKeyPair();
    const raw = await X25519.exportKeyToRaw(keyPair.publicKey);
    const jwk = await X25519.exportKeyToJWK(keyPair.privateKey);

    const importedPub = await X25519.importPublicKey(raw);
    const importedPriv = await X25519.importPrivateKey(jwk);

    const secret = await X25519.deriveSecret(importedPriv, importedPub);
    expect(secret).toBeInstanceOf(Uint8Array);
  });
});
