// Lean Index: maps agent_name -> signed AgentAddr. Pointers only — no endpoints or capabilities.
// See NANDA-L1-DESIGN.md §8.2.

import { generateKeyPair, addProof, type KeyPair } from './crypto.js';
import type { AgentAddr, Secured } from './types.js';

export class LeanIndex {
  private store = new Map<string, Secured<AgentAddr>>();
  readonly keypair: KeyPair;

  private constructor(keypair: KeyPair) {
    this.keypair = keypair;
  }

  static async create(): Promise<LeanIndex> {
    return new LeanIndex(await generateKeyPair());
  }

  get did(): string {
    return this.keypair.did;
  }

  async register(addr: AgentAddr): Promise<Secured<AgentAddr>> {
    const signed = await addProof(addr, this.keypair);
    this.store.set(addr.agent_name, signed);
    return signed;
  }

  resolve(name: string): Secured<AgentAddr> | undefined {
    return this.store.get(name);
  }

  // Test seam: inject a (possibly tampered) record without re-signing.
  injectForTesting(name: string, record: Secured<AgentAddr>): void {
    this.store.set(name, record);
  }
}
