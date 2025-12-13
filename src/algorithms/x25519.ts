import type { AgreementProvider } from '../models/provider.model';
import type {
  X25519KeyPair,
  X25519PrivateKey,
  X25519PublicKey,
} from '../types/key';
import {
  asKeyPair,
  exportKeyToJWK,
  exportKeyToRaw,
  importKey,
} from '../utils/key';

export const X25519: AgreementProvider<X25519PublicKey, X25519PrivateKey> = {
  async generateKeyPair(extractable = true) {
    const keyPair = await globalThis.crypto.subtle.generateKey(
      { name: 'X25519', namedCurve: 'X25519' },
      extractable,
      ['deriveKey', 'deriveBits'],
    );
    return asKeyPair<X25519KeyPair>(keyPair);
  },

  importPublicKey(keyData, extractable = true) {
    return importKey<X25519PublicKey>(keyData, 'X25519', [], extractable);
  },

  importPrivateKey(keyData, extractable = true) {
    return importKey<X25519PrivateKey>(
      keyData,
      'X25519',
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

  async deriveSecret(privateKey, publicKey) {
    const secret = await globalThis.crypto.subtle.deriveBits(
      {
        name: 'X25519',
        public: publicKey,
      },
      privateKey,
      256,
    );
    return new Uint8Array(secret);
  },
};
