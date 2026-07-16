// RFC 8446 §4.1.3 — the TLS 1.3 downgrade-protection sentinel.
//
// A TLS 1.3-capable server that ends up negotiating an older version MUST write a
// fixed 8-byte string into the last 8 bytes of ServerHello.random. A TLS 1.3
// client that sees it knows an active attacker forced the version down and aborts.
//
// This is a WEAKER defense than transcript binding, for reasons the panel shows:
//   • it only signals VERSION rollback (1.3→1.2/1.1), not group/suite stripping;
//   • it is a flag to be *checked*, not a value the agreed key depends on — a
//     client that forgets the check gets no protection;
//   • it lives in one field, not a MAC over the whole transcript.

import { bytesEqual } from './bytes';

// "DOWNGRD" = 44 4F 57 4E 47 52 44, then a version marker byte.
const DOWNGRD = new Uint8Array([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44]);

/** Sentinel written when a TLS 1.3 server negotiates TLS 1.2. */
export const SENTINEL_TLS12 = new Uint8Array([...DOWNGRD, 0x01]);
/** Sentinel written when a TLS 1.3 server negotiates TLS 1.1 or below. */
export const SENTINEL_TLS11_OR_BELOW = new Uint8Array([...DOWNGRD, 0x00]);

export type NegotiatedVersion = 'TLS1.3' | 'TLS1.2' | 'TLS1.1-';

/** The 8 sentinel bytes a spec-compliant server writes for a negotiated version. */
export function sentinelFor(version: NegotiatedVersion): Uint8Array | null {
  if (version === 'TLS1.2') return SENTINEL_TLS12;
  if (version === 'TLS1.1-') return SENTINEL_TLS11_OR_BELOW;
  return null; // TLS 1.3: no sentinel, negotiation was not rolled back
}

export interface ServerRandom {
  /** Last 8 bytes of ServerHello.random (the sentinel slot). */
  tail: Uint8Array;
}

/**
 * Build the last 8 bytes of ServerHello.random. A compliant server writes the
 * sentinel; a `writeSentinel: false` server (the deliberately-broken variant)
 * leaves random bytes there, which is what makes the rollback undetectable.
 */
export function serverRandomTail(
  version: NegotiatedVersion,
  writeSentinel: boolean,
  randomTail: Uint8Array,
): ServerRandom {
  const sentinel = sentinelFor(version);
  if (writeSentinel && sentinel) return { tail: new Uint8Array(sentinel) };
  return { tail: new Uint8Array(randomTail.slice(0, 8)) };
}

export type SentinelCheck =
  | { detected: true; version: NegotiatedVersion }
  | { detected: false };

/**
 * The client-side check. Returns detected:true only if the client both (a) is
 * running the check and (b) sees a sentinel. `clientChecks: false` models the
 * client that never looks — the sentinel is present but useless.
 */
export function checkSentinel(tail: Uint8Array, clientChecks: boolean): SentinelCheck {
  if (!clientChecks) return { detected: false };
  if (bytesEqual(tail, SENTINEL_TLS12)) return { detected: true, version: 'TLS1.2' };
  if (bytesEqual(tail, SENTINEL_TLS11_OR_BELOW)) return { detected: true, version: 'TLS1.1-' };
  return { detected: false };
}
