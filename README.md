# Downgrade Wire

**Negotiation stripping & transcript binding · RFC 8446**

An interactive, in-browser demo of a TLS 1.3 downgrade: two endpoints that both
support the post-quantum group `X25519MLKEM768` end up agreeing on bare `x25519`,
because an on-path attacker deleted one line from a list. Then it shows the fix —
and why the fix works — by turning the TLS 1.3 Finished MAC on and watching the
same strip fail.

## What It Is

When a TLS connection starts, the client sends a `supported_groups` list (its key
exchange options, in preference order) and the server picks one. This negotiation
happens **before authentication** — so an attacker on the wire can edit the list,
and neither endpoint has yet proven anything that would let them notice.

This lab builds that negotiation and one real defense against tampering with it:

- **Real key exchange.** X25519 and ML-KEM-768 (FIPS 203) are **consumed verbatim
  from the sibling lab [`crypto-lab-hybrid-wire`](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/)** — this lab does not
  reimplement them. When a suite is negotiated, a genuine handshake really runs and
  a real shared key is derived.
- **Real transcript binding, hand-rolled.** The TLS 1.3 key schedule
  (`HKDF-Extract` / `HKDF-Expand-Label` / `Derive-Secret`) and the Finished MAC
  (`HMAC(finished_key, Transcript-Hash(...))`) are implemented from RFC 8446 §7.1 /
  §4.4.4. The construction is reproduced **byte-for-byte against the RFC 8448
  client Finished trace**, and its primitives against RFC 5869, RFC 4231, and
  FIPS 180-4 known-answer tests. This is the teaching subject, so it is written out
  in the open, not hidden in a library. The modelled ClientHello carries a real
  `key_share` per group, so stripping the hybrid entry deletes its full ~1.2 KB
  public key from the transcript, not just a codepoint.

**Security model:** the whole point is that the *cryptographic result* and the
*security verdict* are separate. A handshake can report "COMPLETED ✓" and still be
a security failure — a silent downgrade renders as **ALARM**, never green.

**This is not production crypto.** It is a teaching demo. There is no real network,
no certificate/authentication step, and the "unbound" mode is a deliberately-broken
counterfactual used to show what TLS 1.3 prevents.

## Exhibits

1. **What is negotiation stripping?** — a plain-language, zero-math on-ramp: what
   the negotiation is, why it happens before authentication, and the one question
   that decides whether a strip works.
2. **Break it yourself: strip the offer** — the headline interaction. Hit **▶ Play
   the downgrade** for the canonical story in one click, or **Compare unbound vs
   TLS 1.3** to see both worlds side by side from a single action, or drive it
   manually: delete `X25519MLKEM768` and press Run, watching the `supported_groups`
   bytes fly down the wire while the attacker snips the hybrid entry mid-flight. Read
   two separate indicators — the cryptographic result and the security verdict —
   and expand "Show the Finished MAC" for the causal chain: the stripped codepoint
   changes the transcript hash, which changes the MAC, byte-diff highlighted at each
   stage. **Copy link** deep-links any scenario (e.g. `#scenario=strip-bound-preferred`).
3. **One config line: PQC preferred vs required** — the same strip under both server
   policies, side by side. Identical code; one setting turns a silent downgrade into
   a loud failure.
4. **The weaker cousin: the downgrade sentinel** — RFC 8446 §4.1.3's `DOWNGRD`
   magic bytes in `ServerHello.random`, and why a sentinel is weaker than transcript
   binding (narrow scope, opt-in check, single field).
5. **Downgrade by denial of service** — transcript binding makes the strip fail
   *closed*, but a fail-open retry policy that drops PQ on error hands the attacker
   the downgrade anyway.
6. **The same shape, for thirty years** — FREAK, Logjam, and POODLE as the same
   negotiation-before-authentication pattern.
7. **What is real, and what this does not prove** — the honest scope boundary and
   the non-goals, each linking to the sibling lab that owns it.

## When to Use It

- **Use it** to understand *why* TLS 1.3 resists downgrade where TLS 1.2 and SSL 3.0
  did not, and to see that the answer is "the agreed key depends on everything that
  was said," not "the protocol detects tampering."
- **Use it** to explain to a team migrating to PQC that "PQC preferred" and "PQC
  required" are not the same threat model.
- **Do NOT use it** as a TLS implementation, a downgrade scanner, or evidence that a
  given deployment is safe. It models one property in isolation; a real stack has
  many more moving parts (version negotiation, cipher suites, ALPN, session
  resumption) that this lab deliberately omits.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-downgrade-wire/>**

Strip the hybrid group, run the handshake both unbound and bound, flip the server
policy, and drive the sentinel and fail-open panels — every result is computed by
the real key exchange and the real Finished verifier in your browser.

## What Can Go Wrong

- **Silent downgrade (the alarm).** Without transcript binding, a stripped offer
  completes on the weaker suite and nobody is notified. This weakens the **key
  exchange** only: recorded traffic becomes exposed to future quantum decryption
  ("harvest now, decrypt later"). It does **not** compromise authentication or
  signing keys, and no attacker can read the traffic today.
- **Downgrade by denial of service.** Binding makes the strip fail closed, but if
  the client's reaction to failure is "retry with a smaller offer," an attacker who
  can break the connection twice still walks it back to classical-only.
- **Availability cost of "required."** "PQC required" prevents the silent downgrade
  but converts it into a hard failure — its own attack surface.

## Real-World Usage

TLS 1.3 (RFC 8446) is the negotiation and transcript binding modeled here; it is
what protects the vast majority of HTTPS traffic. `X25519MLKEM768`
(draft-kwiatkowski-tls-ecdhe-mlkem, IANA NamedGroup `0x11EC`) is the hybrid
post-quantum group now being deployed across browsers and CDNs. The downgrade
sentinel (RFC 8446 §4.1.3) ships in every TLS 1.3 stack. The historical attacks —
FREAK, Logjam, POODLE — are why this binding exists.

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173
npm test           # unit tests + KATs (Vitest)
npm run build      # typecheck + production build
npm run test:a11y  # axe-core WCAG 2.1 A/AA gate (both themes)
```

## Related Demos

- [`crypto-lab-hybrid-wire`](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — the X25519 + ML-KEM-768 hybrid key exchange this lab consumes.
- [`crypto-lab-hybrid-guide`](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/) — how and why hybrid key exchange composes two KEMs.
- [`crypto-lab-tls-handshake`](https://systemslibrarian.github.io/crypto-lab-tls-handshake/) — the full TLS 1.3 handshake this lab draws one slice from.
- [`crypto-lab-harvest-timeline`](https://systemslibrarian.github.io/crypto-lab-harvest-timeline/) — the "harvest now, decrypt later" threat that makes the downgrade matter.

## Build & Verify

**33 tests across 6 files (Vitest), all passing**, including these known-answer tests:

- `src/negotiation/transcript.test.ts` — HKDF-Extract/Expand against **RFC 5869**
  Appendix A.1; `finished_key = HKDF-Expand-Label(traffic_secret, "finished", "",
  32)` against the **RFC 8448** Simple 1-RTT Handshake trace; the **client Finished
  verify_data reproduced byte-for-byte** from that trace's `finished_key` and
  transcript hash; and HMAC-SHA256 / SHA-256 against **RFC 4231** and **FIPS 180-4**.
- `src/negotiation/sentinel.test.ts` — the `DOWNGRD\x01` / `DOWNGRD\x00` sentinel
  bytes from **RFC 8446 §4.1.3**.
- `src/negotiation/groups.test.ts` — the IANA NamedGroup codepoints
  (`X25519MLKEM768 = 0x11EC`, `x25519 = 0x001D`) and the `supported_groups` wire
  encoding (RFC 8446 §4.2.7).
- `src/kex/kex.test.ts` — X25519 against the **RFC 7748 §5.2** vectors, ML-KEM-768
  (FIPS 203) encaps/decaps round-trip and sizes, and a **deterministic seeded
  ML-KEM-768 KAT** pinning the exact parameter set — proving the consumed KEX is
  genuine and unchanged.
- `src/negotiation/handshake.test.ts` — the negotiation logic: honest PQ handshake,
  the strip completing unbound (result COMPLETED / verdict ALARM — the separation),
  the strip aborting bound (with the 1,222-byte key_share deletion asserted), policy
  preferred-vs-required, and degenerate cases.
- `src/negotiation/failopen.test.ts` — fail-closed vs fail-open retry outcomes.

**Narrative-correctness gate:** `e2e/strip.spec.ts` (Playwright) asserts the copy
that appears with each outcome — unbound-strip ⇒ `COMPLETED` + `DOWNGRADE — ALARM`,
bound-strip ⇒ `ABORTED` + `DEFENSE HELD` with the downgrade "aha" *absent* — because
in a teaching demo, the text next to a result is part of correctness.

**Accessibility gate:** `@axe-core/playwright` scans the production build for zero
WCAG 2.1 A/AA violations in **both** themes (`e2e/a11y.spec.ts`), and the GitHub
Pages deploy is blocked if it (or the narrative gate) fails.

## Performance

The full key exchange (X25519 + ML-KEM-768) plus the key schedule runs in a few
milliseconds per handshake, entirely in the browser; no operation blocks the UI.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
