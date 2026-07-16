// Downgrade by denial of service. Transcript binding makes a strip fail CLOSED —
// the handshake aborts. But if the client's reaction to failure is "retry with a
// smaller offer," an attacker who can break the connection twice walks it back to
// the weak suite anyway. The primitive held; the retry policy gave it away.

import { GROUPS, type GroupId } from './groups';
import { runHandshake } from './handshake';
import type { HandshakeResult } from './types';

export type RetryPolicy = 'fail-open' | 'fail-closed';

export interface FailOpenAttempt {
  label: string;
  offer: GroupId[];
  result: HandshakeResult;
}

export type FailOpenVerdict =
  | 'FAIL_OPEN_DOWNGRADE' // retry dropped PQ and completed on the weak suite
  | 'FAIL_CLOSED_NO_CONNECTION'; // client refused to weaken; no downgrade, no service

export interface FailOpenResult {
  policy: RetryPolicy;
  attempts: FailOpenAttempt[];
  verdict: FailOpenVerdict;
  consequence: string;
}

const FULL_OFFER: GroupId[] = ['X25519MLKEM768', 'x25519'];
const REDUCED_OFFER: GroupId[] = ['x25519'];
const SERVER_SUPPORTED: GroupId[] = ['X25519MLKEM768', 'x25519'];

/**
 * Two rounds against an active attacker:
 *   1. Full PQ-first offer. The attacker strips the hybrid group; transcript
 *      binding aborts the handshake (it fails CLOSED — the correct behavior).
 *   2. The client's retry policy decides what happens next.
 */
export async function simulateFailOpen(policy: RetryPolicy): Promise<FailOpenResult> {
  // Round 1: real strip, real transcript binding → genuine abort.
  const first = await runHandshake({
    clientOffer: FULL_OFFER,
    stripped: ['X25519MLKEM768'],
    serverSupported: SERVER_SUPPORTED,
    transcriptBinding: true,
    policy: 'preferred',
  });

  const attempts: FailOpenAttempt[] = [
    { label: 'Attempt 1 — PQ-first offer', offer: FULL_OFFER, result: first },
  ];

  if (policy === 'fail-closed') {
    return {
      policy,
      attempts,
      verdict: 'FAIL_CLOSED_NO_CONNECTION',
      consequence:
        'The client treats the abort as final and does not retry with a weaker offer. The attacker has denied service but gained nothing: no session key exists, so there is nothing to decrypt now or later.',
    };
  }

  // Round 2: the client "helpfully" drops the group that seemed to cause trouble.
  // No strip is needed now — the client downgraded itself.
  const second = await runHandshake({
    clientOffer: REDUCED_OFFER,
    stripped: [],
    serverSupported: SERVER_SUPPORTED,
    transcriptBinding: true,
    policy: 'preferred',
  });
  attempts.push({ label: 'Attempt 2 — client retries without PQ', offer: REDUCED_OFFER, result: second });

  return {
    policy,
    attempts,
    verdict: 'FAIL_OPEN_DOWNGRADE',
    consequence:
      `Attempt 2 completes on ${GROUPS['x25519'].label}, and every byte of it is validly bound — the Finished MAC matches, because the client really did offer only ${GROUPS['x25519'].label} the second time. Transcript binding cannot help: it proves what was said, and this time the client said "no PQ." The downgrade rode in on the retry, not on a forged transcript.`,
  };
}
