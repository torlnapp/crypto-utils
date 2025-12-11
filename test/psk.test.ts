import { describe, expect, it } from 'bun:test';

import { derivePskBytes, generateRandomPskBytes } from '../src/crypto/psk';

describe('psk helpers', () => {
  it('generates 32 random bytes', () => {
    const first = generateRandomPskBytes();
    const second = generateRandomPskBytes();

    expect(first.length).toBe(32);
    expect(second.length).toBe(32);
    expect(first).not.toEqual(second);
  });

  it('derives deterministic HKDF bytes', async () => {
    const seed = new Uint8Array(
      Array.from({ length: 32 }, (_, idx) => idx + 1),
    );
    const salt = 'unit-test-salt';
    const info = 'psk-info';

    const first = await derivePskBytes(seed, salt, info);
    const second = await derivePskBytes(seed, salt, info);

    expect(first.length).toBe(32);
    expect(first).toEqual(second);
    expect(Array.from(first).some((value) => value !== 0)).toBe(true);
  });
});
