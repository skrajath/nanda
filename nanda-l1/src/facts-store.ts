// Facts Store: hosts issuer-signed AgentFacts documents at opaque URLs.
// Separate component from the index so the index↔facts decoupling is structural, not just conceptual.
// See NANDA-L1-DESIGN.md §8.4.

import { generateKeyPair, addProof, type KeyPair } from './crypto.js';
import type { AgentFacts, Secured } from './types.js';

export class FactsStore {
  private store = new Map<string, Secured<AgentFacts>>();
  readonly keypair: KeyPair;

  private constructor(keypair: KeyPair) {
    this.keypair = keypair;
  }

  static async create(): Promise<FactsStore> {
    return new FactsStore(await generateKeyPair());
  }

  get did(): string {
    return this.keypair.did;
  }

  async host(facts: Omit<AgentFacts, 'issuer'>): Promise<{ url: string; signed: Secured<AgentFacts> }> {
    const withIssuer: AgentFacts = { ...facts, issuer: this.keypair.did };
    const signed = await addProof(withIssuer, this.keypair);
    const url = `facts://${facts.agent_name}`;
    this.store.set(url, signed);
    return { url, signed };
  }

  fetch(url: string): Secured<AgentFacts> | undefined {
    return this.store.get(url);
  }

  // Test seam: inject a (possibly tampered) record without re-signing.
  injectForTesting(url: string, record: Secured<AgentFacts>): void {
    this.store.set(url, record);
  }
}
