// Small byte helpers for the negotiation model. No crypto here — see transcript.ts.

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Constant-time-ish equality (length-independent short-circuit is intentional). */
export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i] ^ right[i];
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function toHexSpaced(bytes: Uint8Array, take?: number): string {
  const slice = typeof take === 'number' ? bytes.slice(0, take) : bytes;
  return Array.from(slice, (b) => b.toString(16).padStart(2, '0')).join(' ');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('hex string must have even length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

export function shortHex(bytes: Uint8Array | undefined, take = 10): string {
  if (!bytes || bytes.length === 0) return '—';
  const hex = toHex(bytes);
  const visible = take * 2;
  return hex.length <= visible ? hex : hex.slice(0, visible) + '…';
}

/** TLS-style uint16, big-endian. */
export function u16(value: number): Uint8Array {
  if (value < 0 || value > 0xffff) throw new Error(`u16 out of range: ${value}`);
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

const textEncoder = new TextEncoder();
export function utf8(text: string): Uint8Array {
  return textEncoder.encode(text);
}
