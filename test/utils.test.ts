import { describe, expect, it } from 'bun:test';

import { cm } from '../src/utils/common';
import { base64, decodeMsgPack, encodeMsgPack } from '../src/utils/encode';

describe('encoding helpers', () => {
  it('encodes bytes to base64', async () => {
    const data = new TextEncoder().encode('hello bun');
    const encoded = await base64(data);
    expect(encoded).toBe('aGVsbG8gYnVu');
  });

  it('round-trips data through msgpack', () => {
    const payload = { foo: 'bar', nested: { count: 2 } };
    const encoded = encodeMsgPack(payload);
    const decoded = decodeMsgPack(encoded as Uint8Array);
    expect(decoded).toEqual(payload);
  });

  it('canonicalizes then encodes payloads', () => {
    const packed = cm({ b: 2, a: 'first' });
    const decoded = decodeMsgPack(packed as Uint8Array);
    expect(decoded).toBe('{"a":"first","b":2}');
  });
});
