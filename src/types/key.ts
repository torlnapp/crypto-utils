import type { webcrypto } from 'node:crypto';
import type { Brand } from './brand';

export type CryptoKey = webcrypto.CryptoKey;
export type CryptoKeyPair = webcrypto.CryptoKeyPair;
export type JsonWebKey = webcrypto.JsonWebKey;

export type AESKey = Brand<webcrypto.CryptoKey, 'AESKey'>;
export type HKDFKey = Brand<webcrypto.CryptoKey, 'HKDF:secret'>;

export type Ed25519PublicKey = Brand<webcrypto.CryptoKey, 'Ed25519:public'>;
export type Ed25519PrivateKey = Brand<webcrypto.CryptoKey, 'Ed25519:private'>;
export type Ed25519KeyPair = KeyPair<Ed25519PublicKey, Ed25519PrivateKey>;

export type X25519PublicKey = Brand<webcrypto.CryptoKey, 'X25519:public'>;
export type X25519PrivateKey = Brand<webcrypto.CryptoKey, 'X25519:private'>;
export type X25519KeyPair = KeyPair<X25519PublicKey, X25519PrivateKey>;

export type PublicKey = Ed25519PublicKey | X25519PublicKey;
export type PrivateKey = Ed25519PrivateKey | X25519PrivateKey;

export type SymmetricKey = AESKey | HKDFKey;
export type Key = PublicKey | PrivateKey | SymmetricKey;
export type KeyPair<P = PublicKey, S = PrivateKey> = {
  publicKey: P;
  privateKey: S;
};

export type KeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey';
export type Algorithm = 'AES-GCM' | 'Ed25519' | 'X25519' | 'HKDF';
