import { toHex } from '../negotiation/bytes';
import { GROUPS, encodeSupportedGroups, type GroupId } from '../negotiation/groups';
import { runHandshake } from '../negotiation/handshake';
import { simulateFailOpen, type RetryPolicy } from '../negotiation/failopen';
import { checkSentinel, serverRandomTail } from '../negotiation/sentinel';
import type { HandshakeConfig, Policy } from '../negotiation/types';
import { clear, h, panel } from './dom';
import { LABS } from './links';
import {
  byteRegion,
  groupChip,
  macDiff,
  resultIndicator,
  sessionKeyLine,
  verdictIndicator,
} from './render';

const FULL_OFFER: GroupId[] = ['X25519MLKEM768', 'x25519'];
const SERVER_SUPPORTED: GroupId[] = ['X25519MLKEM768', 'x25519'];

function radioField(
  legend: string,
  name: string,
  options: { value: string; label: string; note?: string; checked?: boolean }[],
  onChange: (value: string) => void,
): HTMLElement {
  const fs = h('fieldset', { class: 'ctl-modes' }, h('legend', { text: legend }));
  for (const o of options) {
    const input = h('input', {
      attrs: { type: 'radio', name, id: `${name}-${o.value}`, value: o.value, ...(o.checked ? { checked: 'checked' } : {}) },
      on: { change: () => onChange(o.value) },
    });
    fs.append(
      h('span', { class: 'mode-opt' },
        input,
        h('label', { attrs: { for: `${name}-${o.value}` } },
          o.label,
          o.note ? h('span', { class: 'mode-note', text: ` — ${o.note}` }) : null,
        ),
      ),
    );
  }
  return fs;
}

// ── 1. Intro — plain language, zero hex (the highest-leverage teaching fix) ────

export function introPanel(): HTMLElement {
  return panel('intro',
    h('h2', { text: 'What is negotiation stripping?' }),
    h('p', { class: 'panel-lede', text:
      'When two machines start a TLS connection, they first agree on which cryptography to use. The client sends a list of options it supports, in order of preference, and the server picks one. This negotiation happens in the clear, before either side has proven who it is — so an attacker sitting on the wire can quietly edit the list.' }),
    h('p', { text:
      'Post-quantum migration adds a new, stronger option (a hybrid key exchange) alongside the old one. Both endpoints here support it. But if an attacker deletes that one line from the client’s list, the server never sees it was offered, and both sides settle for the weaker, classical-only option — each believing that was the best the other could do.' }),
    h('p', { class: 'honesty', text:
      'The question this lab answers: can the attacker get away with it? That is decided entirely by one thing — whether the record of what was offered is cryptographically bound into the key that gets agreed. TLS 1.3 binds it. Older protocols did not, and that is the shape of FREAK, Logjam, and POODLE.' }),
  );
}

// ── 2. The strip — headline mechanism + break-it-yourself ─────────────────────

export function stripPanel(): HTMLElement {
  const stripped = new Set<GroupId>();
  let binding = true; // TLS 1.3 default
  let policy: Policy = 'preferred';

  const packetList = h('ul', { class: 'pkt-list', attrs: { role: 'list', 'aria-label': 'ClientHello supported_groups, most preferred first' } });
  const attackerLane = h('div', { class: 'lane lane-attacker' });
  const serverLane = h('div', { class: 'lane lane-server' });
  const results = h('div', { class: 'strip-results', attrs: { 'aria-live': 'polite' } });

  // Purposeful, action-triggered animation of the strip itself: on Run, the
  // supported_groups bytes fly client → attacker → server, and the attacker
  // deletes the hybrid codepoint mid-flight (the byte string visibly shrinks).
  // aria-hidden — it re-illustrates what the lanes and results already state in
  // text, so it adds nothing for a screen reader and is decorative to it.
  const OFFER_HEX = toHex(encodeSupportedGroups(FULL_OFFER));
  const packetCode = h('code', { class: 'flight-code', text: OFFER_HEX });
  const packet = h('div', { class: 'flight-packet' }, packetCode);
  const flight = h('div', { class: 'flight', attrs: { 'aria-hidden': 'true' } },
    h('p', { class: 'flight-caption', text: 'The supported_groups bytes travel the wire; the attacker cuts the hybrid entry in transit. Press Run.' }),
    h('div', { class: 'flight-track' },
      h('span', { class: 'flight-tick tick-client', text: 'Client' }),
      h('span', { class: 'flight-tick tick-attacker', text: 'Attacker ✂' }),
      h('span', { class: 'flight-tick tick-server', text: 'Server' }),
      packet,
    ),
  );
  const wait = (ms: number) => new Promise<void>((res) => setTimeout(res, ms));

  function restPacket(): void {
    packet.classList.remove('at-attacker', 'at-server', 'snip');
    packetCode.textContent = OFFER_HEX;
  }
  const resetPacket = restPacket;

  async function playFlight(): Promise<void> {
    const sentHex = toHex(encodeSupportedGroups(FULL_OFFER.filter((id) => !stripped.has(id))));
    const didStrip = stripped.size > 0;
    const reduce = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

    packet.classList.remove('at-attacker', 'at-server', 'snip');
    packetCode.textContent = OFFER_HEX;
    if (reduce) { packetCode.textContent = didStrip ? sentHex : OFFER_HEX; return; }
    void packet.offsetWidth; // reflow so the transition starts at the client end
    packet.classList.add('at-attacker');
    await wait(470);
    if (didStrip) { packetCode.textContent = sentHex; packet.classList.add('snip'); }
    packet.classList.add('at-server');
    await wait(520);
    // Drift back to the client rest state so the widget never idles as a lone
    // chip stranded at the server. Non-blocking: results render immediately.
    setTimeout(restPacket, 720);
  }

  function renderPacket(): void {
    clear(packetList);
    for (const id of FULL_OFFER) {
      if (stripped.has(id)) continue;
      packetList.append(
        groupChip(id, {
          removable: true,
          onRemove: () => {
            stripped.add(id);
            renderPacket();
            renderAttacker();
          },
        }),
      );
    }
    if (FULL_OFFER.every((id) => stripped.has(id))) {
      packetList.append(h('li', { class: 'pkt-empty', text: 'every option stripped — nothing left to offer' }));
    }
  }

  function renderAttacker(): void {
    clear(attackerLane);
    attackerLane.append(h('span', { class: 'lane-title', text: 'On-path attacker' }));
    if (stripped.size === 0) {
      attackerLane.append(h('p', { class: 'lane-idle', text: 'passing bytes through untouched' }));
      return;
    }
    attackerLane.append(h('span', { class: 'scissors', text: '✂', attrs: { 'aria-hidden': 'true' } }));
    const struck = h('ul', { class: 'pkt-list pkt-list-struck', attrs: { role: 'list', 'aria-label': 'Entries the attacker deleted' } });
    for (const id of FULL_OFFER) {
      if (stripped.has(id)) struck.append(groupChip(id, { struck: true }));
    }
    attackerLane.append(struck);
  }

  async function run(): Promise<void> {
    const config: HandshakeConfig = {
      clientOffer: FULL_OFFER,
      stripped: [...stripped],
      serverSupported: SERVER_SUPPORTED,
      transcriptBinding: binding,
      policy,
    };
    const r = await runHandshake(config);
    await playFlight();

    clear(serverLane);
    serverLane.append(h('span', { class: 'lane-title', text: 'Server' }));
    serverLane.append(
      h('p', { class: 'lane-pick' },
        r.negotiatedGroup
          ? h('span', {}, 'ServerHello selects ', h('strong', { text: GROUPS[r.negotiatedGroup].label }))
          : 'aborts — no mutually supported group',
      ),
    );

    clear(results);
    results.append(
      h('div', { class: 'indicator-pair' }, resultIndicator(r.crypto), verdictIndicator(r.verdict)),
      h('p', { class: 'consequence', text: r.consequence }),
      sessionKeyLine(r.sessionKey),
    );
    if (r.finished) {
      results.append(
        h('details', { class: 'expert' },
          h('summary', { text: 'Show the Finished MAC — compute both sides and compare' }),
          macDiff(r.finished),
        ),
      );
    }
    if (r.bothSidesSupportedPQ && r.negotiatedGroup === 'x25519') {
      results.append(
        h('p', { class: 'aha', text:
          'Both endpoints support X25519MLKEM768. The wire agreed x25519. Under an unbound negotiation, neither side ever learns the stronger option was on the table.' }),
      );
    }
  }

  renderPacket();
  renderAttacker();

  return panel('strip',
    h('h2', { text: 'Break it yourself: strip the offer' }),
    h('p', { class: 'panel-lede', text:
      'This runs a real X25519 and real ML-KEM-768 key exchange (consumed from the hybrid-wire lab) and a hand-rolled TLS 1.3 Finished MAC. Delete the hybrid entry from the ClientHello, then run the handshake against the real verifier.' }),
    h('ol', { class: 'guide' },
      h('li', { text: 'Click ✕ on X25519MLKEM768 to strip it from the offer.' }),
      h('li', { text: 'Switch binding to "Unbound" and run — the handshake completes on x25519. Success is the alarm.' }),
      h('li', { text: 'Switch binding back to "TLS 1.3" and run the same strip — the handshake aborts. That is the defense.' }),
    ),
    h('div', { class: 'wire' },
      h('div', { class: 'lane lane-client' },
        h('span', { class: 'lane-title', text: 'Client → ClientHello' }),
        h('span', { class: 'lane-sub', text: 'supported_groups (preference order)' }),
        packetList,
      ),
      h('span', { class: 'wire-arrow', text: '→', attrs: { 'aria-hidden': 'true' } }),
      attackerLane,
      h('span', { class: 'wire-arrow', text: '→', attrs: { 'aria-hidden': 'true' } }),
      serverLane,
    ),
    flight,
    h('div', { class: 'controls' },
      radioField('Transcript binding', 'binding', [
        { value: 'unbound', label: 'Unbound (pre-TLS-1.3 model)', note: 'deliberately broken', checked: false },
        { value: 'bound', label: 'TLS 1.3 (transcript-bound)', note: 'the real default', checked: true },
      ], (v) => { binding = v === 'bound'; }),
      radioField('Server policy', 'policy', [
        { value: 'preferred', label: 'PQC preferred', checked: true },
        { value: 'required', label: 'PQC required' },
      ], (v) => { policy = v as Policy; }),
      h('div', { class: 'btn-row' },
        h('button', { class: 'btn btn-primary', text: 'Run handshake', attrs: { type: 'button', id: 'strip-run' }, on: { click: () => void run() } }),
        h('button', { class: 'btn', text: 'Reset offer', attrs: { type: 'button', id: 'strip-reset' },
          on: { click: () => { stripped.clear(); renderPacket(); renderAttacker(); resetPacket(); clear(serverLane); clear(results); } } }),
      ),
    ),
    results,
  );
}

// ── 3. Policy — same strip, PQC preferred vs required, side by side ───────────

export function policyPanel(): HTMLElement {
  const out = h('div', { class: 'policy-grid', attrs: { 'aria-live': 'polite' } });

  async function run(): Promise<void> {
    const base = {
      clientOffer: FULL_OFFER,
      stripped: ['X25519MLKEM768'] as GroupId[],
      serverSupported: SERVER_SUPPORTED,
      transcriptBinding: false, // isolate the policy variable: same unbound strip
    };
    const [preferred, required] = await Promise.all([
      runHandshake({ ...base, policy: 'preferred' }),
      runHandshake({ ...base, policy: 'required' }),
    ]);
    clear(out);
    for (const [name, r] of [['PQC preferred', preferred], ['PQC required', required]] as const) {
      out.append(
        h('div', { class: 'policy-card' },
          h('h3', { text: name }),
          resultIndicator(r.crypto),
          verdictIndicator(r.verdict),
          h('p', { class: 'note', text: r.consequence }),
        ),
      );
    }
  }

  return panel('policy',
    h('h2', { text: 'One config line: PQC preferred vs required' }),
    h('p', { class: 'panel-lede', text:
      'Identical code, identical strip (the attacker removes the hybrid group and there is no transcript binding). The only difference is one server setting. "Preferred" takes whatever survives; "required" refuses anything classical-only.' }),
    h('button', { class: 'btn btn-primary', text: 'Run the same strip under both policies', attrs: { type: 'button', id: 'policy-run' }, on: { click: () => void run() } }),
    out,
    h('p', { class: 'honesty', text:
      '"Required" turns a silent downgrade into a loud failure — better, but not free: the connection dies, which is its own attack surface (next panel).' }),
  );
}

// ── 4. Downgrade sentinel — RFC 8446 §4.1.3 ──────────────────────────────────

export function sentinelPanel(): HTMLElement {
  let writeSentinel = true;
  let clientChecks = true;
  const out = h('div', { class: 'sentinel-out', attrs: { role: 'status', 'aria-live': 'polite' } });

  function render(): void {
    // Scenario: a TLS 1.3-capable server ends up negotiating TLS 1.2 (a version
    // rollback). A compliant server stamps the sentinel into ServerHello.random.
    const randomTail = new Uint8Array([0x9f, 0x12, 0x39, 0xab, 0xcd, 0xef, 0x01, 0x02]);
    const sr = serverRandomTail('TLS1.2', writeSentinel, randomTail);
    const check = checkSentinel(sr.tail, clientChecks);
    clear(out);
    out.append(byteRegion('Last 8 bytes of ServerHello.random', toHex(sr.tail)));
    const caught = check.detected;
    out.append(
      h('p', { class: `chip ${caught ? 'chip-ok' : 'chip-alarm'}` },
        h('span', { class: 'chip-icon', text: caught ? '✓' : '✗', attrs: { 'aria-hidden': 'true' } }),
        ' ',
        caught
          ? 'Rollback DETECTED — client aborts the TLS 1.2 downgrade'
          : writeSentinel
            ? 'Rollback MISSED — the sentinel is present but the client never checks it'
            : 'Rollback MISSED — this server did not write the sentinel',
      ),
    );
  }

  const check = (label: string, checked: boolean, onChange: (v: boolean) => void) =>
    h('span', { class: 'mode-opt' },
      h('input', { attrs: { type: 'checkbox', id: `sen-${label.replace(/\s+/g, '')}`, ...(checked ? { checked: 'checked' } : {}) },
        on: { change: (e) => { onChange((e.target as HTMLInputElement).checked); render(); } } }),
      h('label', { attrs: { for: `sen-${label.replace(/\s+/g, '')}` }, text: label }),
    );

  render();

  return panel('sentinel',
    h('h2', { text: 'The weaker cousin: the downgrade sentinel' }),
    h('p', { class: 'panel-lede' },
      'RFC 8446 §4.1.3 gives TLS 1.3 a second, narrower defense against ',
      h('em', { text: 'version' }),
      ' rollback: a 1.3-capable server that negotiates an older version writes the ASCII string ',
      h('code', { class: 'inline-hex', text: '44 4f 57 4e 47 52 44 01' }),
      ' ("DOWNGRD\\x01") into the last bytes of ServerHello.random. A 1.3 client that sees it knows it was pushed down.',
    ),
    h('fieldset', { class: 'ctl-modes' },
      h('legend', { text: 'Server negotiates TLS 1.2 (a version rollback)' }),
      check('Server writes the sentinel', true, (v) => { writeSentinel = v; }),
      check('Client checks the sentinel', true, (v) => { clientChecks = v; }),
    ),
    out,
    h('h3', { text: 'Why it is weaker than transcript binding' }),
    h('ul', { class: 'reasons', attrs: { role: 'list' } },
      h('li', { attrs: { role: 'listitem' }, text: 'It only signals a version rollback (1.3→1.2). It says nothing about a group or cipher-suite strip inside 1.3 — which is exactly the attack in the panel above.' }),
      h('li', { attrs: { role: 'listitem' }, text: 'It is a flag to be checked, not a value the key depends on. A client that forgets the check gets zero protection, and the handshake still succeeds.' }),
      h('li', { attrs: { role: 'listitem' }, text: 'It lives in one field. Transcript binding is a MAC over everything that was said, so there is no single byte to remember to inspect.' }),
    ),
  );
}

// ── 5. Fail-open — downgrade by denial of service ─────────────────────────────

export function failOpenPanel(): HTMLElement {
  let policy: RetryPolicy = 'fail-open';
  const out = h('div', { class: 'failopen-out', attrs: { 'aria-live': 'polite' } });

  async function run(): Promise<void> {
    const r = await simulateFailOpen(policy);
    clear(out);
    const steps = h('ol', { class: 'attempt-list', attrs: { role: 'list' } });
    for (const a of r.attempts) {
      steps.append(
        h('li', { class: 'attempt', attrs: { role: 'listitem' } },
          h('span', { class: 'attempt-label', text: a.label }),
          h('span', { class: 'attempt-offer', text: `offer: [${a.offer.map((g) => GROUPS[g].label).join(', ')}]` }),
          resultIndicator(a.result.crypto),
        ),
      );
    }
    out.append(steps);
    const win = r.verdict === 'FAIL_OPEN_DOWNGRADE';
    out.append(
      h('p', { class: `chip ${win ? 'chip-alarm' : 'chip-ok'}` },
        h('span', { class: 'chip-icon', text: win ? '✗' : '✓', attrs: { 'aria-hidden': 'true' } }),
        ' ',
        win ? 'DOWNGRADE — the attacker won by breaking the connection twice' : 'NO DOWNGRADE — the client refused to weaken',
      ),
      h('p', { class: 'note', text: r.consequence }),
    );
  }

  return panel('failopen',
    h('h2', { text: 'Downgrade by denial of service' }),
    h('p', { class: 'panel-lede', text:
      'Transcript binding makes the strip fail closed — the handshake aborts. But what does the client do when a handshake fails? If the answer is "retry with a smaller offer," an attacker who can break the connection twice walks it back to the weak suite anyway. The primitive held; the retry policy gave it away.' }),
    radioField('On handshake failure', 'retry', [
      { value: 'fail-open', label: 'Retry without PQ (fail-open)', checked: true },
      { value: 'fail-closed', label: 'Give up (fail-closed)' },
    ], (v) => { policy = v as RetryPolicy; }),
    h('button', { class: 'btn btn-primary', text: 'Run two rounds', attrs: { type: 'button', id: 'failopen-run' }, on: { click: () => void run() } }),
    out,
  );
}

// ── 6. Historical — same shape across decades ─────────────────────────────────

export function historicalPanel(): HTMLElement {
  const card = (name: string, year: string, desc: string) =>
    h('div', { class: 'hist-card' },
      h('h3', {}, name, h('span', { class: 'hist-year', text: ` · ${year}` })),
      h('p', { class: 'note', text: desc }),
    );
  return panel('history',
    h('h2', { text: 'The same shape, for thirty years' }),
    h('p', { class: 'panel-lede', text:
      'Every one of these was a negotiation an attacker could edit before authentication kicked in. The primitive being downgraded changed; the mechanism did not.' }),
    h('div', { class: 'hist-grid' },
      card('FREAK', '2015', 'Forced clients to accept deliberately-weak 512-bit "export-grade" RSA key exchange that both sides could otherwise avoid. The strong option was stripped; the export option was factorable in hours.'),
      card('Logjam', '2015', 'The Diffie–Hellman version of FREAK: downgraded the connection to export-grade 512-bit DH groups, whose parameters were precomputable. Same negotiation-before-authentication gap.'),
      card('POODLE', '2014', 'Forced a rollback from TLS to SSL 3.0, whose CBC padding could be exploited byte by byte. This is the version-rollback threat the RFC 8446 sentinel was written to answer.'),
    ),
    h('p', { class: 'honesty', text:
      'X25519MLKEM768 is the strong option today, and "harvest now, decrypt later" is the export-grade RSA of the quantum era — recorded traffic that only needs the attacker to wait. The defense is the same one TLS 1.3 already ships: bind the transcript.' }),
  );
}

// ── 7. Honest scope / non-goals ───────────────────────────────────────────────

export function scopePanel(): HTMLElement {
  const nongoal = (title: string, body: string, link?: { href: string; text: string }) =>
    h('div', { class: 'nongoal-card' },
      h('h3', { text: title }),
      h('p', { class: 'note', text: body }),
      link ? h('p', { class: 'nongoal-link' }, 'See instead: ', h('a', { attrs: { href: link.href, target: '_blank', rel: 'noopener' }, text: link.text }), '.') : null,
    );

  return panel('scope',
    h('h2', { text: 'What is real, and what this does not prove' }),
    h('div', { class: 'honesty-block' },
      h('p', {}, h('strong', { text: 'Real: ' }), 'the X25519 and ML-KEM-768 key exchange (consumed verbatim from ',
        h('a', { attrs: { href: LABS.hybridWire, target: '_blank', rel: 'noopener' }, text: 'crypto-lab-hybrid-wire' }),
        '), the HKDF-Expand-Label key schedule, and the Finished MAC — all hand-rolled from the RFC and checked against RFC 8448 / RFC 7748 / RFC 5869 known-answer tests. When you strip the offer and run, a genuine handshake really does complete on the weaker suite, and the real Finished verifier really does abort it.'),
      h('p', {}, h('strong', { text: 'Simulated: ' }), 'the wire. There is no TCP, no real ServerHello parsing, no certificate or authentication step — the messages are modelled as just enough bytes for the transcript hash to be honest. The "Unbound" binding mode is a deliberately-broken counterfactual to show what TLS 1.3 prevents; it is never the default.'),
      h('p', {}, h('strong', { text: 'Simplified: ' }), 'the abort is shown as the client rejecting the server’s Finished MAC. In a real TLS 1.3 stack the diverging transcript also changes the handshake traffic keys, so the mismatch usually surfaces one step earlier — the encrypted flight fails to decrypt. Either way the strip fails closed; this demo isolates the Finished MAC because that is the binding you can watch byte for byte.'),
      h('p', {}, h('strong', { text: 'Does NOT prove: ' }), 'that TLS 1.3 is downgrade-proof in general. It shows one property — that binding the transcript defeats a supported_groups strip — and shows two ways around that property (a fail-open retry, and simply never offering PQ). This is a teaching demo, not production crypto.'),
    ),
    h('h3', { text: 'Out of scope (by design)' }),
    h('div', { class: 'nongoal-grid' },
      nongoal('The TLS 1.3 handshake itself', 'No full record layer, key update, or certificate flow — only the negotiation and its transcript binding.', { href: LABS.tlsHandshake, text: 'crypto-lab-tls-handshake' }),
      nongoal('How hybrid key exchange works', 'This lab treats the hybrid KEM as a black box that is either used or stripped. The combiner and its byte layout are taught elsewhere.', { href: LABS.hybridGuide, text: 'crypto-lab-hybrid-guide' }),
      nongoal('Why post-quantum at all', 'The "harvest now, decrypt later" threat model that makes the downgrade matter is its own subject.', { href: LABS.harvestTimeline, text: 'crypto-lab-harvest-timeline' }),
      nongoal('Exhaustive cipher-suite negotiation', 'Only supported_groups is modelled — the one list that carries the PQ vs classical choice. Signature and AEAD negotiation are not in scope.'),
    ),
  );
}
