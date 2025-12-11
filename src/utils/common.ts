import canonicalize from 'canonicalize';
import { encodeMsgPack } from './encode';

export function cm(payload: unknown): Uint8Array<ArrayBuffer> {
  const result = canonicalize(payload);
  if (result === undefined) {
    throw new Error('Failed to canonicalize payload');
  }
  return encodeMsgPack(result);
}
