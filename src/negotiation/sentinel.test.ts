import { describe, expect, it } from 'vitest';
import { toHex } from './bytes';
import {
  SENTINEL_TLS11_OR_BELOW,
  SENTINEL_TLS12,
  checkSentinel,
  sentinelFor,
} from './sentinel';

describe('downgrade sentinel bytes (RFC 8446 §4.1.3)', () => {
  it('TLS 1.2 sentinel is "DOWNGRD\\x01"', () => {
    expect(toHex(SENTINEL_TLS12)).toBe('444f574e47524401');
  });

  it('TLS 1.1-or-below sentinel is "DOWNGRD\\x00"', () => {
    expect(toHex(SENTINEL_TLS11_OR_BELOW)).toBe('444f574e47524400');
  });

  it('a TLS 1.3 negotiation writes no sentinel', () => {
    expect(sentinelFor('TLS1.3')).toBeNull();
    expect(toHex(sentinelFor('TLS1.2')!)).toBe('444f574e47524401');
  });
});

describe('sentinel is opt-in and narrow', () => {
  it('detects rollback only when the client actually checks', () => {
    expect(checkSentinel(SENTINEL_TLS12, true)).toEqual({ detected: true, version: 'TLS1.2' });
    // Present but unchecked → useless (the sentinel is a flag, not a bound key).
    expect(checkSentinel(SENTINEL_TLS12, false)).toEqual({ detected: false });
  });

  it('ignores non-sentinel random tails', () => {
    const randomTail = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(checkSentinel(randomTail, true)).toEqual({ detected: false });
  });
});
