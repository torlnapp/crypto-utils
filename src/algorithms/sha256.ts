import type { HashProvider } from '../models/provider.model';
import { encodeUTF8 } from '../utils/encode';

export const SHA256: HashProvider = {
  async hash(data) {
    const hashBuffer = await globalThis.crypto.subtle.digest(
      'SHA-256',
      typeof data === 'string' ? encodeUTF8(data) : data,
    );
    return new Uint8Array(hashBuffer);
  },
};
