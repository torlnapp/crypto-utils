import type { Binary } from '../types/array';
import type {
  AESKey,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  HKDFKey,
  JsonWebKey,
  Key,
  KeyPair,
  X25519PrivateKey,
  X25519PublicKey,
} from '../types/key';

type GenerateKey<T = Key | KeyPair> = (extractable?: boolean) => Promise<T>;
type ImportKey<T = Key | KeyPair> = (
  keyData: Binary | JsonWebKey,
  extractable?: boolean,
) => Promise<T>;

export interface Extractable<K extends Key> {
  exportKeyToJWK(key: K): Promise<JsonWebKey>;
  exportKeyToRaw(key: K): Promise<Binary>;
}

export interface SymmetricCryptoProvider<K extends AESKey = AESKey>
  extends Extractable<K> {
  generateKey: GenerateKey<K>;
  importKey: ImportKey<K>;
  encrypt(data: Binary, key: K): Promise<Binary>;
  decrypt(data: Binary, key: K): Promise<Binary>;
}

export interface SignatureProvider<
  P extends Ed25519PublicKey = Ed25519PublicKey,
  S extends Ed25519PrivateKey = Ed25519PrivateKey,
> extends Extractable<P | S> {
  generateKeyPair: GenerateKey<KeyPair<P, S>>;
  importKey: ImportKey<P | S>;
  sign(data: Binary, privateKey: S): Promise<Binary>;
  verify(data: Binary, signature: Binary, publicKey: P): Promise<boolean>;
}

export interface HashProvider {
  hash(data: Binary | string): Promise<Binary>;
}

export interface AgreementProvider<
  P extends X25519PublicKey = X25519PublicKey,
  S extends X25519PrivateKey = X25519PrivateKey,
> extends Extractable<P | S> {
  generateKeyPair: GenerateKey<KeyPair<P, S>>;
  importKey: ImportKey<P | S>;
  deriveSecret(privateKey: S, publicKey: P): Promise<Binary>;
}

export interface DerivationProvider<K extends HKDFKey> extends Extractable<K> {
  generateKey: GenerateKey<K>;
  importKey: ImportKey<K>;
  deriveKey(
    key: K,
    salt: Binary | string,
    info: Binary | string,
    extractable?: boolean,
  ): Promise<AESKey>;
  deriveBits(
    key: K,
    salt: Binary | string,
    info: Binary | string,
  ): Promise<Binary>;
}
