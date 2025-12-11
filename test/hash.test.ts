import { describe, expect, it } from 'bun:test';

import { sha256, sha256Hex } from '../src/crypto/hash';

const helloHex =
  '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

describe('hash utilities', () => {
  it('computes sha256 hex for strings', async () => {
    const digest = await sha256Hex('hello');
    expect(digest).toBe(helloHex);
  });

  it('returns Uint8Array bytes for sha256', async () => {
    const bytes = await sha256('hello');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);

    const hexFromBytes = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    expect(hexFromBytes).toBe(helloHex);
  });
});
