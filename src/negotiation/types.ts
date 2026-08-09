import type { GroupId } from './groups';

export type Policy = 'preferred' | 'required';

export interface HandshakeConfig {
  /** Ordered supported_groups the client actually sends (most-preferred first). */
  clientOffer: GroupId[];
  /** Groups the on-path attacker deletes from the ClientHello in flight. */
  stripped: GroupId[];
  /** Groups the server supports (it selects the client's top choice among these). */
  serverSupported: GroupId[];
  /**
   * TLS 1.3 transcript binding (the Finished MAC over the handshake).
   * `true` = real TLS 1.3. `false` = the deliberately-broken counterfactual: a
   * negotiation whose agreed key does NOT depend on what was offered.
   */
  transcriptBinding: boolean;
  /** "PQC preferred" accepts any mutual group; "PQC required" refuses classical-only. */
  policy: Policy;
}

/** What the crypto actually did — a fact, reported independently of the verdict. */
export type CryptoOutcome =
  | { kind: 'completed'; group: GroupId }
  | { kind: 'aborted'; reason: 'finished-mismatch' | 'policy-reject' }
  | { kind: 'no-shared-group' };

/** Security verdict — tracks system integrity, never the raw return value. */
export type Verdict =
  | 'SECURE' // PQ group agreed and the handshake completed
  | 'DOWNGRADE_ALARM' // a weaker suite was silently agreed — the attack succeeded
  | 'DEFENSE_HELD' // a strip was attempted and transcript binding aborted it
  | 'POLICY_DENIED' // required-PQ refused the downgraded suite (no secret lost, no service)
  | 'NO_CONNECTION'; // no mutually acceptable group at all

export interface FinishedEvidence {
  /** The two supported_groups lists that entered each side's transcript. */
  clientOfferHex: string;
  serverSawHex: string;
  /** SHA-256 transcript hash each side computed over ClientHello…ServerHello. */
  clientTranscriptHash: Uint8Array;
  serverTranscriptHash: Uint8Array;
  /** Total ClientHello bytes the attacker deleted (codepoint + its key_share). */
  bytesStripped: number;
  /**
   * Labels of the groups the attacker actually deleted — EMPTY when it deleted
   * nothing. The UI needs this to describe the deletion truthfully: a
   * transcript-bound handshake produces a `FinishedEvidence` whether or not a
   * strip happened, so neither "what was removed" nor "whether anything was"
   * can be inferred from the presence of this record.
   */
  strippedLabels: string[];
  /** server Finished verify_data as sent, and as the client recomputed it. */
  serverFinishedSent: Uint8Array;
  serverFinishedExpectedByClient: Uint8Array;
  /** True iff the client's recomputation matched — i.e. the transcripts agree. */
  verified: boolean;
}

export interface HandshakeResult {
  config: HandshakeConfig;
  clientSentList: GroupId[];
  serverReceivedList: GroupId[];
  negotiatedGroup: GroupId | null;
  /** Real session key both sides derived for the negotiated group (equal bytes). */
  sessionKey: Uint8Array | null;
  bothSidesSupportedPQ: boolean;
  crypto: CryptoOutcome;
  verdict: Verdict;
  /** Present whenever a handshake with transcript binding was actually attempted. */
  finished: FinishedEvidence | null;
  /** One-line, exactly-true consequence statement for the UI (Constraint B). */
  consequence: string;
}
