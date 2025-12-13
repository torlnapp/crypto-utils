import type { Binary } from '../types/array';
import type {
  Algorithm,
  CryptoKey,
  CryptoKeyPair,
  JsonWebKey,
  Key,
  KeyPair,
  KeyUsage,
  PrivateKey,
  PublicKey,
  SymmetricKey,
} from '../types/key';
import { isBinary } from './binary';
import { getAlgorithmIdentifier } from './crypto';

export function asSymmetricKey<K extends SymmetricKey>(key: CryptoKey): K {
  if (key.type !== 'secret') {
    throw new TypeError('The provided key is not a symmetric key.');
  }
  return key as K;
}

export function asPublicKey<P extends PublicKey>(key: CryptoKey): P {
  if (key.type !== 'public') {
    throw new TypeError('The provided key is not a public key.');
  }
  return key as P;
}

export function asPrivateKey<S extends PrivateKey>(key: CryptoKey): S {
  if (key.type !== 'private') {
    throw new TypeError('The provided key is not a private key.');
  }
  return key as S;
}

export function asKeyPair<P extends KeyPair>(keyPair: CryptoKeyPair): P {
  return {
    publicKey: asPublicKey(keyPair.publicKey),
    privateKey: asPrivateKey(keyPair.privateKey),
  } as P;
}

export function isJWK(key: unknown): key is JsonWebKey {
  return (
    typeof key === 'object' &&
    key !== null &&
    ('kty' in key || 'crv' in key || 'x' in key || 'y' in key)
  );
}

export function importKey<T extends Key>(
  keyData: Binary | JsonWebKey,
  algorithm: Algorithm,
  usage: Array<KeyUsage>,
  extractable = true,
): Promise<T> {
  if (isBinary(keyData)) {
    return importKeyFromRaw(
      keyData,
      algorithm,
      usage,
      extractable,
    ) as Promise<T>;
  } else if (isJWK(keyData)) {
    return importKeyFromJWK(
      keyData,
      algorithm,
      usage,
      extractable,
    ) as Promise<T>;
  } else {
    return Promise.reject(new TypeError('Invalid key format or key type.'));
  }
}

export function importKeyFromJWK(
  jwk: JsonWebKey,
  algorithm: Algorithm,
  usage: Array<KeyUsage>,
  extractable = true,
): Promise<Key> {
  return globalThis.crypto.subtle.importKey(
    'jwk',
    jwk,
    getAlgorithmIdentifier(algorithm),
    extractable,
    usage,
  ) as Promise<Key>;
}

export function importKeyFromRaw(
  raw: Binary,
  algorithm: Algorithm,
  usage: Array<KeyUsage>,
  extractable = true,
): Promise<Key> {
  return globalThis.crypto.subtle.importKey(
    'raw',
    raw,
    getAlgorithmIdentifier(algorithm),
    extractable,
    usage,
  ) as Promise<Key>;
}

export async function exportKeyToJWK(key: Key): Promise<JsonWebKey> {
  return globalThis.crypto.subtle.exportKey('jwk', key);
}

export async function exportKeyToRaw(key: Key): Promise<Binary> {
  const raw = await globalThis.crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}
