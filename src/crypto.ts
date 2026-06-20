// eddsa-jcs-2022 Data Integrity cryptosuite over Ed25519.
// See NANDA-L1-DESIGN.md §8.3 for the rationale behind every choice here.

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { base58 } from '@scure/base';
import canonicalize from 'canonicalize';
import type { DataIntegrityProof, Secured } from './types.js';

const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  did: string;
  verificationMethod: string; // did:key:z...#z...
}

export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const did = encodeDid(publicKey);
  const fragment = did.slice('did:key:'.length);
  return { privateKey, publicKey, did, verificationMethod: `${did}#${fragment}` };
}

// did:key encode: Ed25519 multicodec (0xed01) + multibase base58btc (z prefix)
function encodeDid(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed.set(ED25519_MULTICODEC);
  prefixed.set(publicKey, 2);
  return `did:key:z${base58.encode(prefixed)}`;
}

// Accepts either a did:key:z... or a did:key:z...#z... verification method URL.
export function didToPublicKey(verificationMethodOrDid: string): Uint8Array {
  const did = verificationMethodOrDid.includes('#')
    ? verificationMethodOrDid.split('#')[0]
    : verificationMethodOrDid;
  if (!did.startsWith('did:key:z'))
    throw new Error(`Not a base58btc did:key: ${did}`);
  const bytes = base58.decode(did.slice('did:key:z'.length));
  if (bytes[0] !== 0xed || bytes[1] !== 0x01)
    throw new Error(`Not an Ed25519 did:key (multicodec mismatch): ${did}`);
  return bytes.slice(2);
}

// eddsa-jcs-2022: SHA-256(JCS(proofConfig)) || SHA-256(JCS(document))
function buildHashData(document: object, proofConfig: object): Uint8Array {
  const configHash = sha256(new TextEncoder().encode(canonicalize(proofConfig) ?? ''));
  const docHash = sha256(new TextEncoder().encode(canonicalize(document) ?? ''));
  const combined = new Uint8Array(64);
  combined.set(configHash);
  combined.set(docHash, 32);
  return combined;
}

export async function addProof<T extends object>(
  document: T,
  keypair: KeyPair,
  created?: string,
): Promise<Secured<T>> {
  const proofConfig: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: created ?? new Date().toISOString(),
    verificationMethod: keypair.verificationMethod,
    proofPurpose: 'assertionMethod',
  };

  const hashData = buildHashData(document, proofConfig);
  const sig = await ed.signAsync(hashData, keypair.privateKey);
  return { ...document, proof: { ...proofConfig, proofValue: `z${base58.encode(sig)}` } };
}

export interface VerifyResult {
  valid: boolean;
  issuerDid: string;
  reason?: string;
}

export async function verifyProof<T extends object>(secured: Secured<T>): Promise<VerifyResult> {
  const { proof, ...document } = secured as Record<string, unknown>;
  const p = proof as DataIntegrityProof;
  const issuerDid = p.verificationMethod.includes('#')
    ? p.verificationMethod.split('#')[0]
    : p.verificationMethod;

  let publicKey: Uint8Array;
  try {
    publicKey = didToPublicKey(p.verificationMethod);
  } catch (e) {
    return { valid: false, issuerDid, reason: `Key resolution failed: ${(e as Error).message}` };
  }

  const { proofValue, ...proofConfig } = p;
  if (!proofValue.startsWith('z'))
    return { valid: false, issuerDid, reason: 'proofValue missing multibase z prefix' };

  const sig = base58.decode(proofValue.slice(1));
  const hashData = buildHashData(document, proofConfig);

  const valid = await ed.verifyAsync(sig, hashData, publicKey);
  return { valid, issuerDid, reason: valid ? undefined : 'Signature verification failed' };
}
