// The negotiation state machine: ClientHello → (attacker) → ServerHello →
// key exchange → Finished. The key exchange is genuine and consumed from
// hybrid-wire; the object under attack is the supported_groups negotiation and
// whether the transcript is bound into the agreed key.

import { concatBytes, toHex, u16 } from './bytes';
import { GROUPS, encodeKeyShareEntry, encodeSupportedGroups, type GroupId } from './groups';
import {
  deriveFinishedKey,
  deriveHandshakeSecrets,
  finishedMac,
  transcriptHash,
} from './transcript';
import type { CryptoOutcome, HandshakeConfig, HandshakeResult, Verdict } from './types';
import { generateX25519KeyPair, x25519SharedSecret, type X25519KeyPair } from '../kex/x25519';
import {
  generateMLKEMKeyPair,
  mlkemDecapsulate,
  mlkemEncapsulate,
  type MLKEMKeyPair,
} from '../kex/mlkem768';

// ── Handshake message serialization (with real key_shares) ───────────────────
// The ClientHello carries both the supported_groups list AND a key_share entry
// per offered group. For X25519MLKEM768 that entry is the ~1.2 KB hybrid public
// key, so a strip deletes far more than two codepoint bytes — and every deleted
// byte was inside the transcript the Finished MAC commits to.

function u24(value: number): Uint8Array {
  return new Uint8Array([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}

function handshakeMessage(type: number, body: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([type]), u24(body.length), body);
}

/** The client's per-group key material — real public bytes plus private keys. */
interface ClientShare {
  pub: Uint8Array; // the bytes that go into the key_share entry
  x25519: X25519KeyPair;
  mlkem: MLKEMKeyPair | null;
}

async function makeClientShare(id: GroupId): Promise<ClientShare> {
  const x25519 = await generateX25519KeyPair();
  if (!GROUPS[id].postQuantum) {
    return { pub: x25519.publicKeyRaw, x25519, mlkem: null };
  }
  const mlkem = await generateMLKEMKeyPair();
  // Hybrid client share: ML-KEM-768 encapsulation key ‖ X25519 public key.
  // draft-kwiatkowski-tls-ecdhe-mlkem puts the ML-KEM part first for
  // X25519MLKEM768 (and the ECDHE part first for SecP256r1MLKEM768).
  return { pub: concatBytes(mlkem.publicKey, x25519.publicKeyRaw), x25519, mlkem };
}

async function makeClientShares(offer: GroupId[]): Promise<Map<GroupId, ClientShare>> {
  const map = new Map<GroupId, ClientShare>();
  for (const id of offer) map.set(id, await makeClientShare(id));
  return map;
}

function encodeClientHello(
  offer: GroupId[],
  clientRandom: Uint8Array,
  shares: Map<GroupId, ClientShare>,
): Uint8Array {
  // client_hello(1): random ‖ supported_groups ‖ key_share (one entry per group)
  const keyShare = concatBytes(
    ...offer.map((id) => encodeKeyShareEntry(id, shares.get(id)!.pub)),
  );
  return handshakeMessage(0x01, concatBytes(clientRandom, encodeSupportedGroups(offer), keyShare));
}

function encodeServerHello(selected: GroupId, serverRandom: Uint8Array): Uint8Array {
  // server_hello(2): random ‖ the single selected group
  return handshakeMessage(0x02, concatBytes(serverRandom, u16(GROUPS[selected].codepoint)));
}

// ── Real key exchange for the negotiated group ───────────────────────────────

export interface KexDetail {
  sessionKey: Uint8Array;
  x25519Secret: Uint8Array;
  mlkemSecret: Uint8Array | null;
  usedPQ: boolean;
}

// draft-ietf-tls-hybrid-design: the hybrid shared secret concatenates the two
// component secrets. The exact combiner/wire layout is the subject of the
// sibling lab crypto-lab-hybrid-wire and is intentionally not taught here. The
// server completes the exchange against the client's real key_share.
async function completeKex(group: GroupId, clientShare: ClientShare): Promise<KexDetail> {
  const serverX = await generateX25519KeyPair();

  // X25519 ECDHE — both sides derive the identical secret (this is what the
  // strip leaves untouched, which is why the downgraded handshake still works).
  const [zClient, zServer] = await Promise.all([
    x25519SharedSecret(clientShare.x25519.privateKey, serverX.publicKeyRaw),
    x25519SharedSecret(serverX.privateKey, clientShare.x25519.publicKeyRaw),
  ]);
  void zServer; // equal to zClient by construction; kept to model both endpoints

  if (!GROUPS[group].postQuantum || !clientShare.mlkem) {
    return { sessionKey: zClient, x25519Secret: zClient, mlkemSecret: null, usedPQ: false };
  }

  // Server encapsulates against the client's ML-KEM encapsulation key; the client
  // decapsulates with its private key — a genuine ML-KEM-768 exchange.
  const { sharedSecret: kemServer, ciphertext } = await mlkemEncapsulate(clientShare.mlkem.publicKey);
  const kemClient = await mlkemDecapsulate(ciphertext, clientShare.mlkem.privateKey);
  const sessionKey = concatBytes(kemClient, zClient);
  return { sessionKey, x25519Secret: zClient, mlkemSecret: kemServer, usedPQ: true };
}

// ── Negotiation ──────────────────────────────────────────────────────────────

/** Server picks the client's most-preferred received group that it supports. */
function selectGroup(received: GroupId[], serverSupported: GroupId[]): GroupId | null {
  for (const g of received) {
    if (serverSupported.includes(g)) return g;
  }
  return null;
}

function applyStrip(offer: GroupId[], stripped: GroupId[]): GroupId[] {
  return offer.filter((g) => !stripped.includes(g));
}

function listsEqual(a: GroupId[], b: GroupId[]): boolean {
  return a.length === b.length && a.every((g, i) => g === b[i]);
}

function consequenceFor(verdict: Verdict, group: GroupId | null): string {
  switch (verdict) {
    case 'SECURE':
      return group && GROUPS[group].postQuantum
        ? 'Both endpoints agreed X25519MLKEM768. The session key mixes in the ML-KEM-768 secret, so traffic recorded today stays confidential even against a future quantum computer.'
        : 'The handshake completed on the group both sides offered — no stronger option was stripped.';
    case 'DOWNGRADE_ALARM':
      return 'Both endpoints support X25519MLKEM768, yet the agreed key is pure X25519. Confidentiality now rests on the elliptic-curve discrete-log problem alone, so recorded traffic is exposed to future quantum decryption (harvest-now, decrypt-later). This weakens the KEY EXCHANGE only — authentication and signing keys are untouched, and no attacker can read this traffic today.';
    case 'DEFENSE_HELD':
      return 'The client Finished commits to the list it actually sent; the server built its transcript over the stripped list. The MACs diverge, so the endpoint aborts before any application data flows. Transcript binding detects the strip — it does not repair it.';
    case 'POLICY_DENIED':
      return '"PQC required" refuses to finish a classical-only handshake, so no downgraded key is ever established. The cost is availability: the connection fails, which an attacker can weaponize (see the Fail-open panel).';
    case 'NO_CONNECTION':
      return 'No group the client offered survived to one the server supports, so the handshake cannot proceed.';
  }
}

export async function runHandshake(config: HandshakeConfig): Promise<HandshakeResult> {
  const clientSentList = [...config.clientOffer];
  const serverReceivedList = applyStrip(clientSentList, config.stripped);
  const negotiatedGroup = selectGroup(serverReceivedList, config.serverSupported);

  const bothSidesSupportedPQ =
    clientSentList.some((g) => GROUPS[g].postQuantum) &&
    config.serverSupported.some((g) => GROUPS[g].postQuantum);

  const base = {
    config,
    clientSentList,
    serverReceivedList,
    bothSidesSupportedPQ,
  };

  if (!negotiatedGroup) {
    return {
      ...base,
      negotiatedGroup: null,
      sessionKey: null,
      crypto: { kind: 'no-shared-group' } as CryptoOutcome,
      verdict: 'NO_CONNECTION',
      finished: null,
      consequence: consequenceFor('NO_CONNECTION', null),
    };
  }

  // The client generates real key_shares for every group it offers; the server
  // completes the exchange against the client's share for the negotiated group.
  const shares = await makeClientShares(clientSentList);
  const kex = await completeKex(negotiatedGroup, shares.get(negotiatedGroup)!);
  const isPQ = GROUPS[negotiatedGroup].postQuantum;
  const stripHappened = !listsEqual(clientSentList, serverReceivedList);
  const policyReject = config.policy === 'required' && !isPQ;

  // Fixed randoms shared across both endpoint views: the attacker edits only the
  // ClientHello's group list and its key_shares, so these are identical on both.
  const clientRandom = crypto.getRandomValues(new Uint8Array(32));
  const serverRandom = crypto.getRandomValues(new Uint8Array(32));
  const serverHello = encodeServerHello(negotiatedGroup, serverRandom);

  const clientHello = encodeClientHello(clientSentList, clientRandom, shares);
  const serverHelloSawCH = encodeClientHello(serverReceivedList, clientRandom, shares);
  const clientView = [clientHello, serverHello];
  const serverView = [serverHelloSawCH, serverHello];
  const bytesStripped = clientHello.length - serverHelloSawCH.length;

  let crypto_: CryptoOutcome;
  let verdict: Verdict;
  let finished = null as HandshakeResult['finished'];

  if (config.transcriptBinding) {
    // Real TLS 1.3: the handshake traffic secrets — and thus the Finished keys —
    // are derived from (ECDHE ∪ transcript), and the Finished MAC covers the
    // transcript. Two independent bindings, both broken by a strip.
    const clientSecrets = deriveHandshakeSecrets(kex.sessionKey, clientView);
    const serverSecrets = deriveHandshakeSecrets(kex.sessionKey, serverView);
    const serverFinishedSent = finishedMac(
      deriveFinishedKey(serverSecrets.serverHandshakeTrafficSecret),
      serverView,
    );
    const serverFinishedExpectedByClient = finishedMac(
      deriveFinishedKey(clientSecrets.serverHandshakeTrafficSecret),
      clientView,
    );
    const verified =
      serverFinishedSent.length === serverFinishedExpectedByClient.length &&
      serverFinishedSent.every((b, i) => b === serverFinishedExpectedByClient[i]);

    finished = {
      clientOfferHex: toHex(encodeSupportedGroups(clientSentList)),
      serverSawHex: toHex(encodeSupportedGroups(serverReceivedList)),
      clientTranscriptHash: transcriptHash(clientView),
      serverTranscriptHash: transcriptHash(serverView),
      bytesStripped,
      // What the attacker actually removed, in client preference order. Empty on
      // a clean run — which is a state the UI must render, since a bound
      // handshake always builds this record.
      strippedLabels: clientSentList
        .filter((g) => !serverReceivedList.includes(g))
        .map((g) => GROUPS[g].label),
      serverFinishedSent,
      serverFinishedExpectedByClient,
      verified,
    };

    if (!verified) {
      crypto_ = { kind: 'aborted', reason: 'finished-mismatch' };
      verdict = 'DEFENSE_HELD';
    } else if (policyReject) {
      crypto_ = { kind: 'aborted', reason: 'policy-reject' };
      verdict = 'POLICY_DENIED';
    } else {
      crypto_ = { kind: 'completed', group: negotiatedGroup };
      verdict = isPQ ? 'SECURE' : 'DOWNGRADE_ALARM';
    }
  } else {
    // Deliberately-broken counterfactual: the agreed key does NOT depend on the
    // offered list, and there is no Finished check. This is the shape of
    // pre-TLS-1.3 negotiation, and it is never the default in the UI.
    if (policyReject) {
      crypto_ = { kind: 'aborted', reason: 'policy-reject' };
      verdict = 'POLICY_DENIED';
    } else {
      crypto_ = { kind: 'completed', group: negotiatedGroup };
      verdict = isPQ ? 'SECURE' : stripHappened ? 'DOWNGRADE_ALARM' : 'SECURE';
    }
  }

  const completed = crypto_.kind === 'completed';
  return {
    ...base,
    negotiatedGroup,
    sessionKey: completed ? kex.sessionKey : null,
    crypto: crypto_,
    verdict,
    finished,
    consequence: consequenceFor(verdict, negotiatedGroup),
  };
}
