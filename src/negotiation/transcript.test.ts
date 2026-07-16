import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { hexToBytes, toHex, utf8 } from './bytes';
import {
  deriveFinishedKey,
  finishedMac,
  finishedMacFromTranscriptHash,
  hkdfExpand,
  hkdfExpandLabel,
  hkdfExtract,
  transcriptHash,
} from './transcript';

describe('HKDF (RFC 5869 known-answer test, Appendix A.1 / SHA-256)', () => {
  const IKM = hexToBytes('0b'.repeat(22));
  const SALT = hexToBytes('000102030405060708090a0b0c');
  const INFO = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
  const PRK = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
  const OKM =
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

  it('HKDF-Extract matches PRK', () => {
    expect(toHex(hkdfExtract(SALT, IKM))).toBe(PRK);
  });

  it('HKDF-Expand matches OKM (L=42)', () => {
    expect(toHex(hkdfExpand(hexToBytes(PRK), INFO, 42))).toBe(OKM);
  });
});

describe('HKDF-Expand-Label / finished_key (RFC 8448 §3, Simple 1-RTT Handshake)', () => {
  // Handshake traffic secrets and finished keys straight from RFC 8448. Deriving
  // the finished keys from the traffic secrets exercises HKDF-Expand-Label with
  // the exact "tls13 finished" label and empty context the Finished MAC uses.
  const CHTS = hexToBytes('b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21');
  const SHTS = hexToBytes('b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38');
  const CLIENT_FINISHED_KEY =
    'b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4';
  const SERVER_FINISHED_KEY =
    '008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8';

  it('client finished_key = HKDF-Expand-Label(CHTS, "finished", "", 32)', () => {
    expect(toHex(deriveFinishedKey(CHTS))).toBe(CLIENT_FINISHED_KEY);
  });

  it('server finished_key = HKDF-Expand-Label(SHTS, "finished", "", 32)', () => {
    expect(toHex(deriveFinishedKey(SHTS))).toBe(SERVER_FINISHED_KEY);
  });

  it('HKDF-Expand-Label separates keys by label', () => {
    const a = hkdfExpandLabel(CHTS, 'finished', new Uint8Array(0), 32);
    const b = hkdfExpandLabel(CHTS, 'key', new Uint8Array(0), 32);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('end-to-end Finished (RFC 8448 §3, reproduced byte-for-byte)', () => {
  // The client Finished verify_data = HMAC(client_finished_key, Transcript-Hash).
  // Transcript-Hash(ClientHello…server Finished) is the value RFC 8448 prints for
  // the "c ap traffic" / "s ap traffic" derive-secret step — the exact same
  // transcript endpoint the client Finished commits to.
  const CLIENT_FINISHED_KEY = hexToBytes(
    'b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4',
  );
  const TRANSCRIPT_HASH = hexToBytes(
    '9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13',
  );
  const CLIENT_FINISHED = 'a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61';

  it('reproduces the RFC 8448 client Finished verify_data', () => {
    expect(toHex(finishedMacFromTranscriptHash(CLIENT_FINISHED_KEY, TRANSCRIPT_HASH))).toBe(
      CLIENT_FINISHED,
    );
  });

  it('finishedMac(key, messages) == HMAC(key, SHA-256(messages)) — the composition holds', () => {
    const msgs = [utf8('ClientHello…'), utf8('…ServerHello')];
    expect(toHex(finishedMac(CLIENT_FINISHED_KEY, msgs))).toBe(
      toHex(finishedMacFromTranscriptHash(CLIENT_FINISHED_KEY, transcriptHash(msgs))),
    );
  });
});

describe('primitives underneath the Finished (canonical KATs)', () => {
  it('HMAC-SHA256 matches RFC 4231 Test Case 2', () => {
    const mac = hmac(sha256, utf8('Jefe'), utf8('what do ya want for nothing?'));
    expect(toHex(mac)).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });

  it('SHA-256 matches FIPS 180-4 SHA256("abc")', () => {
    expect(toHex(sha256(utf8('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
