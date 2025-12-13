import type { DerivationProvider } from '../models/provider.model';
import type { AESKey, HKDFKey } from '../types/key';
import { encodeUTF8 } from '../utils/encode';
import {
  asSymmetricKey,
  exportKeyToJWK,
  exportKeyToRaw,
  importKey,
} from '../utils/key';

export const HKDF: DerivationProvider<HKDFKey> = {
  async generateKey(extractable = false) {
    const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const key = await globalThis.crypto.subtle.importKey(
      'raw',
      seed,
      { name: 'HKDF' },
      extractable,
      ['deriveKey', 'deriveBits'],
    );

    return asSymmetricKey<HKDFKey>(key);
  },

  async importKey(keyData, extractable = false) {
    return importKey<HKDFKey>(
      keyData,
      'HKDF',
      ['deriveKey', 'deriveBits'],
      extractable,
    );
  },

  exportKeyToJWK(key) {
    return exportKeyToJWK(key);
  },

  exportKeyToRaw(key) {
    return exportKeyToRaw(key);
  },

  async deriveKey(key, salt, info, extractable = false) {
    const derivedKey = await globalThis.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: typeof salt === 'string' ? encodeUTF8(salt) : salt,
        info: typeof info === 'string' ? encodeUTF8(info) : info,
      },
      key,
      { name: 'AES-GCM', length: 256 },
      extractable,
      ['encrypt', 'decrypt'],
    );

    return asSymmetricKey<AESKey>(derivedKey);
  },

  async deriveBits(key, salt, info) {
    const derived = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: typeof salt === 'string' ? encodeUTF8(salt) : salt,
        info: typeof info === 'string' ? encodeUTF8(info) : info,
      },
      key,
      256,
    );

    return new Uint8Array(derived);
  },
};
