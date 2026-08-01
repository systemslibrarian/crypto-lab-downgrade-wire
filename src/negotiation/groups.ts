// TLS 1.3 supported_groups / NamedGroup registry — the objects being negotiated.
//
// Codepoints are the real IANA "TLS Supported Groups" values, so the wire bytes
// shown in the demo are the bytes a real ClientHello would carry.
//   x25519          = 0x001D   (RFC 7748 / RFC 8446)
//   X25519MLKEM768  = 0x11EC   (draft-kwiatkowski-tls-ecdhe-mlkem, IANA 4588)
//   secp256r1       = 0x0017   (kept only for the historical rollback panel)

import { u16 } from './bytes';

export type GroupId = 'X25519MLKEM768' | 'x25519' | 'secp256r1';

export interface NamedGroup {
  /** IANA NamedGroup identifier (the codepoint sent on the wire). */
  readonly id: GroupId;
  readonly codepoint: number;
  /** Human label as it appears in the supported_groups list. */
  readonly label: string;
  /** True when the group provides post-quantum protection (a hybrid KEM). */
  readonly postQuantum: boolean;
  /** One-line description of the key exchange this group runs. */
  readonly kex: string;
}

export const GROUPS: Record<GroupId, NamedGroup> = {
  X25519MLKEM768: {
    id: 'X25519MLKEM768',
    codepoint: 0x11ec,
    label: 'X25519MLKEM768',
    postQuantum: true,
    kex: 'Hybrid: X25519 (ECDHE) + ML-KEM-768 (FIPS 203)',
  },
  x25519: {
    id: 'x25519',
    codepoint: 0x001d,
    label: 'x25519',
    postQuantum: false,
    kex: 'X25519 elliptic-curve Diffie–Hellman (classical only)',
  },
  secp256r1: {
    id: 'secp256r1',
    codepoint: 0x0017,
    label: 'secp256r1',
    postQuantum: false,
    kex: 'NIST P-256 ECDHE (classical only)',
  },
};

export function codepointHex(id: GroupId): string {
  return '0x' + GROUPS[id].codepoint.toString(16).toUpperCase().padStart(4, '0');
}

/**
 * Wire encoding of the supported_groups extension body: a uint16 list length
 * followed by each group's uint16 codepoint (RFC 8446 §4.2.7). This is the exact
 * byte sequence the attacker edits, and it feeds the transcript hash — so the
 * strip is visible in the bytes the Finished MAC commits to.
 */
export function encodeSupportedGroups(order: GroupId[]): Uint8Array {
  const body: number[] = [];
  for (const id of order) {
    const cp = u16(GROUPS[id].codepoint);
    body.push(cp[0], cp[1]);
  }
  const listLen = u16(body.length);
  return new Uint8Array([listLen[0], listLen[1], ...body]);
}

/**
 * Wire encoding of one key_share entry (RFC 8446 §4.2.8): the group's codepoint,
 * a uint16 length, then the key-exchange public bytes. For X25519MLKEM768 the
 * client share is the ~1.2 KB ML-KEM-768 encapsulation key ‖ X25519 public key —
 * so stripping the hybrid group deletes this whole block, not just two codepoint
 * bytes. (The exact hybrid share layout is the subject of crypto-lab-hybrid-wire.)
 */
export function encodeKeyShareEntry(id: GroupId, pub: Uint8Array): Uint8Array {
  const cp = u16(GROUPS[id].codepoint);
  const len = u16(pub.length);
  return new Uint8Array([cp[0], cp[1], len[0], len[1], ...pub]);
}
