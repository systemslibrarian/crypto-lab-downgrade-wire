import { describe, expect, it } from 'vitest';
import { toHex } from './bytes';
import { GROUPS, codepointHex, encodeSupportedGroups } from './groups';

describe('NamedGroup codepoints (IANA TLS Supported Groups)', () => {
  it('uses the real registry values', () => {
    expect(GROUPS.X25519MLKEM768.codepoint).toBe(0x11ec); // 4588
    expect(GROUPS.x25519.codepoint).toBe(0x001d); // 29
    expect(GROUPS.secp256r1.codepoint).toBe(0x0017); // 23
    expect(codepointHex('X25519MLKEM768')).toBe('0x11EC');
  });

  it('marks post-quantum groups correctly', () => {
    expect(GROUPS.X25519MLKEM768.postQuantum).toBe(true);
    expect(GROUPS.x25519.postQuantum).toBe(false);
  });
});

describe('supported_groups wire encoding (RFC 8446 §4.2.7)', () => {
  it('encodes list length + big-endian codepoints', () => {
    // [X25519MLKEM768, x25519] → listLen=0x0004, 11ec, 001d
    expect(toHex(encodeSupportedGroups(['X25519MLKEM768', 'x25519']))).toBe('000411ec001d');
  });

  it('the strip removes exactly the hybrid codepoint from the bytes', () => {
    const full = toHex(encodeSupportedGroups(['X25519MLKEM768', 'x25519']));
    const stripped = toHex(encodeSupportedGroups(['x25519']));
    expect(stripped).toBe('0002001d');
    expect(full).toContain('11ec');
    expect(stripped).not.toContain('11ec');
  });
});
