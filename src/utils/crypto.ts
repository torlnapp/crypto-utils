import type { Binary } from '../types/array';
import type { Algorithm } from '../types/key';

export function generateNonce(): Binary {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  return nonce;
}

export function processCiphertext(payload: Binary): {
  ciphertext: Binary;
  tag: Binary;
} {
  const payloadUint8 = new Uint8Array(payload);
  const tagLength = 16;
  const ciphertext = payloadUint8.slice(0, payloadUint8.length - tagLength);
  const tag = payloadUint8.slice(payloadUint8.length - tagLength);

  return { ciphertext, tag };
}

export function getAlgorithmIdentifier(algorithm: Algorithm) {
  switch (algorithm) {
    case 'AES-GCM':
      return { name: 'AES-GCM' };
    case 'Ed25519':
      return { name: 'Ed25519' };
    case 'X25519':
      return { name: 'X25519' };
    case 'HKDF':
      return { name: 'HKDF' };
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}
