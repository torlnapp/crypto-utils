export async function sha256(
  data: Uint8Array | string,
): Promise<Uint8Array<ArrayBuffer>> {
  const buffer = new Uint8Array(
    typeof data === 'string' ? new TextEncoder().encode(data) : data,
  );
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hashBuffer);
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const hashBytes = await sha256(data);
  return Array.from(hashBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
