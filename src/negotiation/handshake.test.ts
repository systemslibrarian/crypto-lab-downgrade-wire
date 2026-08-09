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

describe('FinishedEvidence.strippedLabels reports what was actually deleted', () => {
  // A transcript-bound handshake builds a FinishedEvidence whether or not a
  // strip happened, so the record's mere presence says nothing about what (or
  // whether) anything was removed. The UI renders a sentence describing the
  // deletion straight off these fields; before `strippedLabels` existed it
  // hardcoded X25519MLKEM768 and derived the key_share length as
  // `bytesStripped - 6`, which on a clean run printed a deletion of 0 bytes
  // "plus its -6-byte X25519MLKEM768 key_share".
  it('is empty, with zero bytes stripped, on a clean bound run', async () => {
    const r = await runHandshake(cfg({ stripped: [], transcriptBinding: true }));
    expect(r.finished).not.toBeNull();
    expect(r.finished!.strippedLabels).toEqual([]);
    expect(r.finished!.bytesStripped).toBe(0);
    expect(r.finished!.verified).toBe(true);
  });

  it('names the hybrid group, and accounts for every deleted byte, when it is stripped', async () => {
    const r = await runHandshake(cfg({ stripped: ['X25519MLKEM768'], transcriptBinding: true }));
    expect(r.finished!.strippedLabels).toEqual(['X25519MLKEM768']);
    // 2 bytes of codepoint in supported_groups; the rest is the key_share entry
    // (a 4-byte header plus the hybrid public key), so the remainder is positive.
    expect(r.finished!.bytesStripped - 2).toBeGreaterThan(0);
  });

  it('names x25519 — not the hybrid — when x25519 is the group removed', async () => {
    const r = await runHandshake(cfg({ stripped: ['x25519'], transcriptBinding: true }));
    expect(r.finished!.strippedLabels).toEqual(['x25519']);
    expect(r.finished!.bytesStripped - 2).toBeGreaterThan(0);
  });
});
