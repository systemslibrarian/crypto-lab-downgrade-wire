import { describe, expect, it } from 'vitest';
import { simulateFailOpen } from './failopen';

describe('downgrade by denial of service', () => {
  it('fail-closed: the abort is final, no key is ever established', async () => {
    const r = await simulateFailOpen('fail-closed');
    expect(r.verdict).toBe('FAIL_CLOSED_NO_CONNECTION');
    expect(r.attempts).toHaveLength(1);
    // Round 1 is a genuine transcript-binding abort (the defense working).
    expect(r.attempts[0].result.crypto).toEqual({ kind: 'aborted', reason: 'finished-mismatch' });
    expect(r.attempts[0].result.verdict).toBe('DEFENSE_HELD');
  });

  it('fail-open: the retry drops PQ and completes on the weak suite', async () => {
    const r = await simulateFailOpen('fail-open');
    expect(r.verdict).toBe('FAIL_OPEN_DOWNGRADE');
    expect(r.attempts).toHaveLength(2);
    // The second handshake is fully valid and bound — that is the point.
    expect(r.attempts[1].result.crypto).toEqual({ kind: 'completed', group: 'x25519' });
    expect(r.attempts[1].result.finished?.verified).toBe(true);
  });
});
