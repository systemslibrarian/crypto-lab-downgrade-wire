// ─────────────────────────────────────────────────────────────────────────────
// VENDORED VERBATIM from crypto-lab-hybrid-wire (src/crypto/x25519.ts).
// SOURCE OF TRUTH is the sibling repo — do NOT edit the crypto here.
//
// This lab (crypto-lab-downgrade-wire) attacks only the *negotiation*; the key
// exchange itself is genuine and is CONSUMED from hybrid-wire per the brief
// ("reuse hybrid-wire's modules — link, don't rebuild"). Reproduced byte-for-byte
// so the demo deploys as a standalone static site (the sibling is not published
// to npm). Real X25519 via @noble/curves, with a WebCrypto-native fast path.
// ─────────────────────────────────────────────────────────────────────────────
import { x25519 as nobleX25519 } from '@noble/curves/ed25519.js';

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}

const subtle = globalThis.crypto?.subtle;
const fallbackPrivateKeys = new WeakMap<object, Uint8Array>();
let nativeSupportPromise: Promise<boolean> | undefined;

function cloneBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

async function supportsNativeX25519(): Promise<boolean> {
  if (!subtle) {
    return false;
  }

  if (!nativeSupportPromise) {
    nativeSupportPromise = subtle
      .generateKey({ name: 'X25519' }, false, ['deriveBits'])
      .then(() => true)
      .catch(() => false);
  }

  return nativeSupportPromise;
}

async function createFallbackPrivateKey(secretKey: Uint8Array): Promise<CryptoKey> {
  if (subtle) {
    try {
      const keyMaterial = cloneBytes(secretKey) as BufferSource;
      const key = await subtle.importKey('raw', keyMaterial, { name: 'HKDF' }, false, ['deriveBits']);
      fallbackPrivateKeys.set(key as object, cloneBytes(secretKey));
      return key as unknown as CryptoKey;
    } catch {
      // Fall through to the light wrapper below.
    }
  }

  const fallbackKey = {
    type: 'private',
    extractable: false,
    algorithm: { name: 'X25519-fallback' },
    usages: ['deriveBits'],
  } as unknown as CryptoKey;

  fallbackPrivateKeys.set(fallbackKey as unknown as object, cloneBytes(secretKey));
  return fallbackKey;
}

async function importNativePublicKey(publicKeyBytes: Uint8Array): Promise<CryptoKey> {
  if (!subtle) {
    throw new Error('Web Crypto is unavailable.');
  }

  const publicKeyMaterial = cloneBytes(publicKeyBytes) as BufferSource;
  return subtle.importKey('raw', publicKeyMaterial, { name: 'X25519' }, true, []);
}

export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  if (await supportsNativeX25519()) {
    const keyPair = (await subtle!.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
    const publicKeyRaw = cloneBytes(new Uint8Array(await subtle!.exportKey('raw', keyPair.publicKey)));

    return {
      publicKey: publicKeyRaw,
      publicKeyRaw,
      privateKey: keyPair.privateKey,
    };
  }

  const privateKeyBytes = cloneBytes(nobleX25519.utils.randomSecretKey());
  const publicKey = cloneBytes(nobleX25519.getPublicKey(privateKeyBytes));

  return {
    publicKey,
    publicKeyRaw: publicKey,
    privateKey: await createFallbackPrivateKey(privateKeyBytes),
  };
}

export async function x25519SharedSecret(
  myPrivateKey: CryptoKey,
  theirPublicKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  const fallbackPrivateKey = fallbackPrivateKeys.get(myPrivateKey as unknown as object);
  if (fallbackPrivateKey) {
    return cloneBytes(nobleX25519.getSharedSecret(cloneBytes(fallbackPrivateKey), cloneBytes(theirPublicKeyBytes)));
  }

  if (!(await supportsNativeX25519())) {
    throw new Error('X25519 is unavailable in this runtime and no fallback key material was provided.');
  }

  const theirPublicKey = await importNativePublicKey(theirPublicKeyBytes);
  const sharedBits = await subtle!.deriveBits(
    { name: 'X25519', public: theirPublicKey },
    myPrivateKey,
    256,
  );

  return cloneBytes(new Uint8Array(sharedBits));
}
