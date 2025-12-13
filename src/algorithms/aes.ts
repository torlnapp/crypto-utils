import type { SymmetricCryptoProvider } from '../models/provider.model';
import type { AESKey } from '../types/key';
import { generateNonce } from '../utils/crypto';
import {
  asSymmetricKey,
  exportKeyToJWK,
  exportKeyToRaw,
  importKey,
} from '../utils/key';

export const AES: SymmetricCryptoProvider<AESKey> = {
  async generateKey(extractable = true) {
    const key = await globalThis.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      extractable,
      ['encrypt', 'decrypt'],
    );
    return asSymmetricKey<AESKey>(key);
  },

  async importKey(keyData, extractable = true) {
    return importKey<AESKey>(
      keyData,
      'AES-GCM',
      ['encrypt', 'decrypt'],
      extractable,
    );
  },

  exportKeyToJWK(key) {
    return exportKeyToJWK(key);
  },

  exportKeyToRaw(key) {
    return exportKeyToRaw(key);
  },

  async encrypt(data, key) {
    const iv = generateNonce();
    const encrypted = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data,
    );
    const encryptedArray = new Uint8Array(encrypted);
    const result = new Uint8Array(iv.length + encryptedArray.length);
    result.set(iv);
    result.set(encryptedArray, iv.length);
    return result;
  },

  async decrypt(data, key) {
    const iv = data.slice(0, 12);
    const encryptedData = data.slice(12);
    const decrypted = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encryptedData,
    );
    return new Uint8Array(decrypted);
  },
};
