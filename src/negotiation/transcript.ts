// ─────────────────────────────────────────────────────────────────────────────
// The teaching subject of this lab, hand-rolled and inspectable: TLS 1.3
// transcript binding. The underlying HMAC-SHA256 is a vetted primitive
// (@noble/hashes); everything TLS-specific — HKDF-Expand-Label, Derive-Secret,
// the key schedule, and the Finished MAC — is spelled out here so a learner can
// read exactly how "the agreed key depends on everything that was said."
//
// References: RFC 8446 §7.1 (key schedule), §4.4.4 (Finished), §7.3;
//             RFC 5869 (HKDF). KATs live in transcript.test.ts (RFC 8448).
// ─────────────────────────────────────────────────────────────────────────────
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, u16, utf8 } from './bytes';

export const HASH_LEN = 32; // SHA-256

/** RFC 5869 HKDF-Extract: PRK = HMAC(salt, IKM). */
export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmac(sha256, salt, ikm);
}

/** RFC 5869 HKDF-Expand, restricted to the ≤ one-hash-block outputs TLS 1.3 uses. */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const blocks = Math.ceil(length / HASH_LEN);
  let t = new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < blocks; i += 1) {
    t = hmac(sha256, prk, concatBytes(t, info, new Uint8Array([i + 1])));
    chunks.push(t);
  }
  return concatBytes(...chunks).slice(0, length);
}

/**
 * RFC 8446 §7.1 HKDF-Expand-Label. The label is prefixed with "tls13 " and the
 * context is length-prefixed, so two derivations that share a secret but differ
 * in label or context produce independent keys.
 *
 *   struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
 */
export function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Uint8Array {
  const fullLabel = utf8('tls13 ' + label);
  const hkdfLabel = concatBytes(
    u16(length),
    new Uint8Array([fullLabel.length]),
    fullLabel,
    new Uint8Array([context.length]),
    context,
  );
  return hkdfExpand(secret, hkdfLabel, length);
}

/** RFC 8446 §7.1 Derive-Secret(Secret, Label, Messages). */
export function deriveSecret(secret: Uint8Array, label: string, transcript: Uint8Array): Uint8Array {
  return hkdfExpandLabel(secret, label, sha256(transcript), HASH_LEN);
}

/** Transcript-Hash = SHA-256 over the concatenated handshake messages so far. */
export function transcriptHash(messages: Uint8Array[]): Uint8Array {
  return sha256(concatBytes(...messages));
}

// ── Key schedule (RFC 8446 §7.1) ─────────────────────────────────────────────
// Enough of the schedule to reach the handshake traffic secrets that key the
// Finished MACs. PSK path is unused here (no resumption), so Early Secret takes a
// zero PSK, exactly as a fresh full handshake does.

const ZEROS = new Uint8Array(HASH_LEN);

export interface HandshakeSecrets {
  handshakeSecret: Uint8Array;
  clientHandshakeTrafficSecret: Uint8Array;
  serverHandshakeTrafficSecret: Uint8Array;
}

/**
 * Derive the handshake traffic secrets from the (EC)DHE shared secret and the
 * ClientHello…ServerHello transcript. `chToSh` is the exact message view of ONE
 * endpoint — this is where a stripped ClientHello makes the two peers diverge.
 */
export function deriveHandshakeSecrets(sharedSecret: Uint8Array, chToSh: Uint8Array[]): HandshakeSecrets {
  const earlySecret = hkdfExtract(ZEROS, ZEROS);
  const derived = deriveSecret(earlySecret, 'derived', new Uint8Array(0));
  const handshakeSecret = hkdfExtract(derived, sharedSecret);
  const thHash = concatBytes(...chToSh);
  return {
    handshakeSecret,
    clientHandshakeTrafficSecret: deriveSecret(handshakeSecret, 'c hs traffic', thHash),
    serverHandshakeTrafficSecret: deriveSecret(handshakeSecret, 's hs traffic', thHash),
  };
}

/** RFC 8446 §4.4.4: finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length). */
export function deriveFinishedKey(baseKey: Uint8Array): Uint8Array {
  return hkdfExpandLabel(baseKey, 'finished', new Uint8Array(0), HASH_LEN);
}

/** RFC 8446 §4.4.4: verify_data = HMAC(finished_key, transcript_hash). */
export function finishedMacFromTranscriptHash(
  finishedKey: Uint8Array,
  th: Uint8Array,
): Uint8Array {
  return hmac(sha256, finishedKey, th);
}

/**
 * RFC 8446 §4.4.4: verify_data = HMAC(finished_key, Transcript-Hash(messages)).
 * The Finished commits the sender to every byte in `messages`; the receiver
 * recomputes it over the messages IT saw. When those views differ (a strip),
 * the two MACs cannot match — that is transcript binding.
 */
export function finishedMac(finishedKey: Uint8Array, messages: Uint8Array[]): Uint8Array {
  return finishedMacFromTranscriptHash(finishedKey, transcriptHash(messages));
}
