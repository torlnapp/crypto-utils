import { describe, expect, it } from 'bun:test';

import { generateAESGCMKey } from '../src/crypto/key';
import { encrypt } from '../src/crypto/method';

describe('encrypt helper', () => {
  it('encrypts data with AES-GCM', async () => {
    const key = await generateAESGCMKey();
    const plaintext = 'secret payload';

    const cipher = await encrypt('AES-GCM', key, plaintext);
    expect(cipher).toBeInstanceOf(Uint8Array);
    expect(cipher.length).toBeGreaterThanOrEqual(plaintext.length + 16);
  });

  it('uses a fresh IV each time', async () => {
    const key = await generateAESGCMKey();
    const first = await encrypt('AES-GCM', key, 'repeatable');
    const second = await encrypt('AES-GCM', key, 'repeatable');

    expect(first).not.toEqual(second);
  });
});
