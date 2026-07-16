import { describe, expect, it } from 'vitest';
import { runHandshake } from './handshake';
import type { GroupId } from './groups';
import type { HandshakeConfig } from './types';

const SERVER: GroupId[] = ['X25519MLKEM768', 'x25519'];
const FULL: GroupId[] = ['X25519MLKEM768', 'x25519'];

function cfg(over: Partial<HandshakeConfig>): HandshakeConfig {
  return {
    clientOffer: FULL,
    stripped: [],
    serverSupported: SERVER,
    transcriptBinding: true,
    policy: 'preferred',
    ...over,
  };
}

describe('honest handshake (no attacker)', () => {
  it('negotiates the PQ hybrid and completes securely', async () => {
    const r = await runHandshake(cfg({}));
    expect(r.negotiatedGroup).toBe('X25519MLKEM768');
    expect(r.crypto).toEqual({ kind: 'completed', group: 'X25519MLKEM768' });
    expect(r.verdict).toBe('SECURE');
    expect(r.finished?.verified).toBe(true);
    // Hybrid session key = ML-KEM secret (32) ‖ X25519 secret (32).
    expect(r.sessionKey).toHaveLength(64);
  });
});

describe('the strip, without transcript binding (the counterfactual)', () => {
  it('completes on the weak suite — success IS the alarm', async () => {
    const r = await runHandshake(cfg({ stripped: ['X25519MLKEM768'], transcriptBinding: false }));
    expect(r.negotiatedGroup).toBe('x25519');
    // Constraint A: cryptographic result and security verdict are SEPARATE and
    // point opposite ways here. The handshake "succeeded"; the verdict is ALARM.
    expect(r.crypto).toEqual({ kind: 'completed', group: 'x25519' });
    expect(r.verdict).toBe('DOWNGRADE_ALARM');
    expect(r.bothSidesSupportedPQ).toBe(true);
    expect(r.sessionKey).toHaveLength(32); // real X25519 key, genuinely established
  });

  it('consequence names encryption-key exposure, not authentication (Constraint B)', async () => {
    const r = await runHandshake(cfg({ stripped: ['X25519MLKEM768'], transcriptBinding: false }));
    expect(r.consequence).toMatch(/KEY EXCHANGE only/);
    expect(r.consequence).toMatch(/authentication and signing keys are untouched/);
    expect(r.consequence).toMatch(/no attacker can read this traffic today/);
  });
});

describe('the same strip, with transcript binding on (the defense)', () => {
  it('aborts: the Finished MACs diverge', async () => {
    const r = await runHandshake(cfg({ stripped: ['X25519MLKEM768'], transcriptBinding: true }));
    expect(r.crypto).toEqual({ kind: 'aborted', reason: 'finished-mismatch' });
    expect(r.verdict).toBe('DEFENSE_HELD');
    expect(r.finished?.verified).toBe(false);
    expect(r.sessionKey).toBeNull();
    // The transcripts genuinely differ, and so do the MACs.
    const f = r.finished!;
    expect(f.clientOfferHex).not.toBe(f.serverSawHex);
    // The strip deleted the hybrid codepoint AND its ~1.2 KB key_share, not just
    // two bytes: 2 (supported_groups) + 4 (key_share header) + 1216 (X25519 ‖ ek).
    expect(f.bytesStripped).toBe(1222);
    expect(Buffer.from(f.serverFinishedSent)).not.toEqual(
      Buffer.from(f.serverFinishedExpectedByClient),
    );
    expect(Buffer.from(f.clientTranscriptHash)).not.toEqual(Buffer.from(f.serverTranscriptHash));
  });
});

describe('policy: PQC preferred vs PQC required (same strip, one config line)', () => {
  it('required refuses the downgraded suite even with binding off', async () => {
    const r = await runHandshake(
      cfg({ stripped: ['X25519MLKEM768'], transcriptBinding: false, policy: 'required' }),
    );
    expect(r.crypto).toEqual({ kind: 'aborted', reason: 'policy-reject' });
    expect(r.verdict).toBe('POLICY_DENIED');
    expect(r.sessionKey).toBeNull();
  });

  it('preferred accepts the downgraded suite (binding off)', async () => {
    const r = await runHandshake(
      cfg({ stripped: ['X25519MLKEM768'], transcriptBinding: false, policy: 'preferred' }),
    );
    expect(r.verdict).toBe('DOWNGRADE_ALARM');
  });
});

describe('degenerate cases', () => {
  it('stripping every group leaves nothing to negotiate', async () => {
    const r = await runHandshake(cfg({ stripped: ['X25519MLKEM768', 'x25519'] }));
    expect(r.negotiatedGroup).toBeNull();
    expect(r.crypto).toEqual({ kind: 'no-shared-group' });
    expect(r.verdict).toBe('NO_CONNECTION');
  });
});
