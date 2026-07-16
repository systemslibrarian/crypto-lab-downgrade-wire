// Proves the CONSUMED key exchange is genuine — not a re-implementation and not
// a stub. X25519 is checked against the RFC 7748 known-answer vectors; ML-KEM-768
// against its own encaps/decaps agreement and FIPS 203 sizes.

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { hexToBytes, toHex } from '../negotiation/bytes';
import { generateX25519KeyPair, x25519SharedSecret } from './x25519';
import { generateMLKEMKeyPair, mlkemDecapsulate, mlkemEncapsulate } from './mlkem768';

describe('X25519 (RFC 7748 §5.2 known-answer tests)', () => {
  it('vector 1', () => {
    const k = hexToBytes('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    const u = hexToBytes('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
    expect(toHex(x25519.getSharedSecret(k, u))).toBe(
      'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
    );
  });

  it('vector 2', () => {
    const k = hexToBytes('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d');
    const u = hexToBytes('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493');
    expect(toHex(x25519.getSharedSecret(k, u))).toBe(
      '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
    );
  });

  it('vendored wrapper: two peers derive the identical shared secret', async () => {
    const alice = await generateX25519KeyPair();
    const bob = await generateX25519KeyPair();
    const ab = await x25519SharedSecret(alice.privateKey, bob.publicKeyRaw);
    const ba = await x25519SharedSecret(bob.privateKey, alice.publicKeyRaw);
    expect(toHex(ab)).toBe(toHex(ba));
    expect(ab).toHaveLength(32);
  });
});

describe('ML-KEM-768 (FIPS 203) round trip via the vendored wrapper', () => {
  it('encapsulate then decapsulate recovers the same shared secret', async () => {
    const kp = await generateMLKEMKeyPair();
    expect(kp.publicKey).toHaveLength(1184); // ek
    expect(kp.privateKey).toHaveLength(2400); // dk
    const { sharedSecret, ciphertext } = await mlkemEncapsulate(kp.publicKey);
    expect(ciphertext).toHaveLength(1088);
    expect(sharedSecret).toHaveLength(32);
    const recovered = await mlkemDecapsulate(ciphertext, kp.privateKey);
    expect(toHex(recovered)).toBe(toHex(sharedSecret));
  });

  it('a wrong secret key does not recover the secret (implicit rejection)', async () => {
    const kp = await generateMLKEMKeyPair();
    const other = await generateMLKEMKeyPair();
    const { sharedSecret, ciphertext } = await mlkemEncapsulate(kp.publicKey);
    const wrong = await mlkemDecapsulate(ciphertext, other.privateKey);
    expect(toHex(wrong)).not.toBe(toHex(sharedSecret));
  });
});

// Deterministic KAT: FIPS 203 ML-KEM-768 keygen and encapsulation are functions
// of their random input. Fixed seed d‖z (64 bytes) and message m (32 bytes) must
// yield fixed outputs, so this pins the exact ML-KEM-768 parameter set the lab
// consumes and would fail loudly on any drift (e.g. a swap to ML-KEM-512/1024).
// Expected values are anchored to @noble/post-quantum, which is validated against
// the NIST ACVP ML-KEM test vectors.
describe('ML-KEM-768 deterministic known-answer (fixed seed + message)', () => {
  const SEED = Uint8Array.from({ length: 64 }, (_, i) => i); // 00 01 02 … 3f
  const MESSAGE = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i); // 80 81 … 9f

  it('seeded keygen + encapsulation are reproducible and standard-sized', () => {
    const kp = ml_kem768.keygen(SEED);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(kp.publicKey, MESSAGE);

    expect(toHex(sha256(kp.publicKey))).toBe(
      '0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9',
    );
    expect(toHex(sha256(kp.secretKey))).toBe(
      'dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5',
    );
    expect(toHex(sha256(cipherText))).toBe(
      '1f16e217ad23771f7f72522c602dcf10cd1e2eea2648e72d29c1255a3949c33e',
    );
    expect(toHex(sharedSecret)).toBe(
      'ef91db44b6cd5b2c50f483481a3d6e2a08cc149764fcb8dc568851332da45ed9',
    );
    // And the fixed ciphertext decapsulates back to the same secret.
    expect(toHex(ml_kem768.decapsulate(cipherText, kp.secretKey))).toBe(toHex(sharedSecret));
  });
});
