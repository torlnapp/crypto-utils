import type { SignatureProvider } from '../models/provider.model';
import type {
  Ed25519KeyPair,
  Ed25519PrivateKey,
  Ed25519PublicKey,
} from '../types/key';
import {
  asKeyPair,
  exportKeyToJWK,
  exportKeyToRaw,
  importKey,
} from '../utils/key';

export const Ed25519: SignatureProvider<Ed25519PublicKey, Ed25519PrivateKey> = {
  async generateKeyPair(extractable = true) {
    const keyPair = await globalThis.crypto.subtle.generateKey(
      { name: 'Ed25519', namedCurve: 'Ed25519' },
      extractable,
      ['sign', 'verify'],
    );
    return asKeyPair<Ed25519KeyPair>(keyPair);
  },

  async importKey(keyData, extractable = true) {
    return importKey<Ed25519PublicKey | Ed25519PrivateKey>(
      keyData,
      'Ed25519',
      ['sign', 'verify'],
      extractable,
    );
  },

  exportKeyToJWK(key) {
    return exportKeyToJWK(key);
  },

  exportKeyToRaw(key) {
    return exportKeyToRaw(key);
  },

  async sign(data, privateKey) {
    const signature = await globalThis.crypto.subtle.sign(
      { name: 'Ed25519' },
      privateKey,
      data,
    );
    return new Uint8Array(signature);
  },

  async verify(data, signature, publicKey) {
    const isValid = await globalThis.crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      signature,
      data,
    );
    return isValid;
  },
};
