import { shortHex, toHex } from '../negotiation/bytes';
import { GROUPS, codepointHex, type GroupId } from '../negotiation/groups';
import type { CryptoOutcome, FinishedEvidence, Verdict } from '../negotiation/types';
import { h } from './dom';

// ── Security verdict (integrity color) — Constraint A / §1 VISUAL SEMANTICS ────
// Color tracks system integrity, never the raw return value. A completed-but-
// downgraded handshake is ALARM red, not success green.

interface VerdictMeta {
  icon: string;
  label: string;
  cls: string;
}

const VERDICT: Record<Verdict, VerdictMeta> = {
  SECURE: { icon: '✓', label: 'SECURE — post-quantum key agreed', cls: 'chip-ok' },
  DOWNGRADE_ALARM: { icon: '✗', label: 'DOWNGRADE — ALARM', cls: 'chip-alarm' },
  DEFENSE_HELD: { icon: '✓', label: 'DEFENSE HELD — strip detected, handshake aborted', cls: 'chip-ok' },
  POLICY_DENIED: { icon: '⚠', label: 'CONNECTION DENIED — required PQ refused the weak suite', cls: 'chip-warn' },
  NO_CONNECTION: { icon: '⚠', label: 'NO SHARED GROUP — handshake cannot proceed', cls: 'chip-warn' },
};

export function verdictIndicator(verdict: Verdict): HTMLElement {
  const m = VERDICT[verdict];
  return h('div', { class: 'indicator' },
    h('span', { class: 'indicator-role', text: 'Security verdict' }),
    h('p', { class: `chip ${m.cls}`, attrs: { role: 'status', 'aria-live': 'polite' } },
      h('span', { class: 'chip-icon', text: m.icon, attrs: { 'aria-hidden': 'true' } }),
      ' ',
      h('span', { text: m.label }),
    ),
  );
}

// ── Cryptographic result (neutral — a reported fact, independent of the verdict) ─

function resultText(crypto: CryptoOutcome): string {
  switch (crypto.kind) {
    case 'completed':
      return `Handshake COMPLETED on ${GROUPS[crypto.group].label}`;
    case 'aborted':
      return crypto.reason === 'finished-mismatch'
        ? 'Handshake ABORTED — Finished MAC mismatch'
        : 'Handshake ABORTED — policy refused a classical-only suite';
    case 'no-shared-group':
      return 'Handshake FAILED — no mutually supported group';
  }
}

export function resultIndicator(crypto: CryptoOutcome): HTMLElement {
  return h('div', { class: 'indicator' },
    h('span', { class: 'indicator-role', text: 'Cryptographic result' }),
    h('p', { class: 'chip chip-neutral', attrs: { role: 'status', 'aria-live': 'polite' } },
      h('span', { class: 'chip-icon', text: 'ℹ', attrs: { 'aria-hidden': 'true' } }),
      ' ',
      h('span', { text: resultText(crypto) }),
    ),
  );
}

// ── ClientHello packet: the deletable supported_groups list ────────────────────

export function groupChip(
  id: GroupId,
  opts: { removable?: boolean; struck?: boolean; onRemove?: () => void } = {},
): HTMLElement {
  const g = GROUPS[id];
  const chip = h('li', { class: `pkt-entry${opts.struck ? ' pkt-struck' : ''}`, attrs: { role: 'listitem' } },
    h('span', { class: `pq-dot ${g.postQuantum ? 'pq-yes' : 'pq-no'}`, attrs: { 'aria-hidden': 'true' } }),
    h('span', { class: 'pkt-name', text: g.label }),
    h('span', { class: 'pkt-code', text: codepointHex(id) }),
    h('span', { class: 'pkt-tag', text: g.postQuantum ? 'post-quantum' : 'classical' }),
  );
  if (opts.removable && opts.onRemove) {
    chip.append(
      h('button', {
        class: 'pkt-remove',
        text: '✕',
        attrs: { type: 'button', 'aria-label': `Strip ${g.label} from the ClientHello` },
        on: { click: opts.onRemove },
      }),
    );
  }
  return chip;
}

// ── Byte / hash rows ───────────────────────────────────────────────────────────

/** Byte positions (each = 2 hex chars) where two hex strings differ. */
function diffIndices(a: string, b: string): Set<number> {
  const out = new Set<number>();
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 2) {
    if (a.slice(i, i + 2) !== b.slice(i, i + 2)) out.add(i / 2);
  }
  return out;
}

/** Render hex as per-byte spans, wrapping differing / marked bytes in <mark>. */
function hexBytesEl(hex: string, mark: Set<number>): HTMLElement {
  const code = h('code', { class: 'byteblock' });
  for (let i = 0; i < hex.length; i += 2) {
    const byte = hex.slice(i, i + 2);
    const idx = i / 2;
    code.append(
      mark.has(idx)
        ? h('mark', { class: 'byte-changed', text: byte })
        : document.createTextNode(byte),
    );
    code.append(document.createTextNode(' '));
  }
  return code;
}

export function byteRegion(label: string, value: string, mark = new Set<number>()): HTMLElement {
  const code = hexBytesEl(value, mark);
  code.setAttribute('role', 'group');
  code.setAttribute('tabindex', '0');
  code.setAttribute('aria-label', label);
  return h('div', { class: 'byterow' }, h('span', { class: 'byterow-label', text: label }), code);
}

function badge(ok: boolean): HTMLElement {
  return h('span', { class: `verify-badge ${ok ? 'vb-ok' : 'vb-fail'}` },
    h('span', { class: 'chip-icon', text: ok ? '✓' : '✗', attrs: { 'aria-hidden': 'true' } }),
    ' ',
    ok ? 'identical' : 'differ',
  );
}

function connector(text: string): HTMLElement {
  return h('p', { class: 'diff-connector' },
    h('span', { class: 'diff-arrow', text: '↓', attrs: { 'aria-hidden': 'true' } }),
    ' ',
    h('span', { text }),
  );
}

/**
 * Describe the deletion the attacker made, in terms of the bytes shown above it.
 *
 * This has to handle the CLEAN run, because a transcript-bound handshake builds
 * a `FinishedEvidence` whether or not anything was stripped — the shipped
 * default configuration (bound, unstripped) opens this very panel and there is
 * nothing to report. It also must not name a group that was not the one
 * removed: stripping only `x25519` is a reachable configuration.
 *
 * Both were wrong before. The line was a single unconditional sentence
 * hardcoding X25519MLKEM768, so a clean run rendered "The attacker deleted 0
 * bytes from the ClientHello: the 2-byte 11ec codepoint plus its -6-byte
 * X25519MLKEM768 key_share" — a negative length, for a deletion that did not
 * happen, naming a group that was still in the offer. The arithmetic is exact:
 * each deleted group costs 2 bytes in supported_groups, and everything else is
 * its key_share entry (a 4-byte header plus the public bytes).
 */
function deletionLine(f: FinishedEvidence): string {
  const n = f.strippedLabels.length;
  if (n === 0) {
    return 'The attacker deleted nothing: the server received the ClientHello byte for byte, so both sides hash the same transcript.';
  }
  const codepointBytes = 2 * n;
  return (
    `The attacker deleted ${f.bytesStripped} bytes from the ClientHello: ` +
    `the ${codepointBytes}-byte codepoint${n > 1 ? 's' : ''} for ` +
    `${f.strippedLabels.join(' and ')} in supported_groups, plus the ` +
    `${f.bytesStripped - codepointBytes} bytes of matching key_share.`
  );
}

// The causal chain, shown not asserted (§2): the stripped codepoint propagates
// through SHA-256 into the transcript hash and through HMAC into the Finished MAC.
export function macDiff(f: FinishedEvidence): HTMLElement {
  const clientTH = toHex(f.clientTranscriptHash);
  const serverTH = toHex(f.serverTranscriptHash);
  const sent = toHex(f.serverFinishedSent);
  const expected = toHex(f.serverFinishedExpectedByClient);

  const hashesMatch = clientTH === serverTH;
  const macsMatch = f.verified;

  // Mark the hybrid codepoint (11ec) inside the client's supported_groups bytes.
  const offerMark = new Set<number>();
  const cp = f.clientOfferHex.indexOf('11ec');
  if (cp >= 0) { offerMark.add(cp / 2); offerMark.add(cp / 2 + 1); }

  return h('div', { class: 'macdiff' },
    h('p', { class: 'diff-stage-label', text: '1 · supported_groups on the wire' }),
    byteRegion('supported_groups the client sent (hybrid codepoint highlighted)', f.clientOfferHex, offerMark),
    byteRegion('supported_groups the server received', f.serverSawHex),
    h('p', { class: 'diff-delete', text: deletionLine(f) }),

    connector('SHA-256 over the full ClientHello … ServerHello'),
    h('p', { class: 'diff-stage-label', text: '2 · Transcript-Hash' }),
    byteRegion('Transcript-Hash (client view)', clientTH, diffIndices(clientTH, serverTH)),
    byteRegion('Transcript-Hash (server view)', serverTH, diffIndices(serverTH, clientTH)),
    badge(hashesMatch),

    connector('HMAC(server_finished_key, Transcript-Hash)'),
    h('p', { class: 'diff-stage-label', text: '3 · server Finished (verify_data)' }),
    byteRegion('server Finished — sent by the server', sent, diffIndices(sent, expected)),
    byteRegion('server Finished — recomputed by the client', expected, diffIndices(expected, sent)),
    badge(macsMatch),

    h('p', { class: 'note', text: macsMatch
      ? 'The two views are identical byte-for-byte, so the hash and the MAC match and the client accepts.'
      : 'A single stripped entry changed the transcript hash, which changed the MAC. The client recomputes the server’s Finished over what it actually sent, the two disagree, and it aborts.' }),
  );
}

export function sessionKeyLine(sessionKey: Uint8Array | null): HTMLElement {
  return h('p', { class: 'note' },
    sessionKey
      ? `Real session key established (${sessionKey.length} bytes): `
      : 'No session key was established.',
    sessionKey ? h('code', { class: 'inline-hex', text: shortHex(sessionKey, 14) }) : null,
  );
}
