// Resolution client + trust policy.
// Orchestrates the full name -> AgentAddr -> AgentFacts chain.
// Two-gate per hop: integrity (verifyProof) then authority (policy check).
// Hard-fail on any step — no fallbacks in L1. See NANDA-L1-DESIGN.md §8.5.

import { verifyProof } from './crypto.js';
import type { AgentAddr, AgentFacts, Secured } from './types.js';
import type { LeanIndex } from './index-service.js';
import type { FactsStore } from './facts-store.js';

export interface TrustPolicy {
  trustedIndex: string;      // DID of the trusted index resolver
  trustedIssuers: string[];  // DIDs of trusted AgentFacts issuers
}

export interface ResolveResult {
  ok: boolean;
  reason?: string;
  addr?: Secured<AgentAddr>;
  facts?: Secured<AgentFacts>;
  endpoint?: string;
  steps: string[];
}

export class NandaClient {
  constructor(
    private readonly index: LeanIndex,
    private readonly factsStore: FactsStore,
    private readonly policy: TrustPolicy,
  ) {}

  async resolve(agentName: string): Promise<ResolveResult> {
    const steps: string[] = [];

    // 1. Lookup
    steps.push(`[1] Lookup "${agentName}" in index`);
    const addr = this.index.resolve(agentName);
    if (!addr) return fail(`Agent not found: ${agentName}`, steps);
    steps.push(`[1] AgentAddr found`);

    // 2. Integrity — verify AgentAddr proof
    steps.push(`[2] Verify AgentAddr proof (integrity)`);
    const addrV = await verifyProof(addr);
    if (!addrV.valid) return fail(`AgentAddr proof invalid: ${addrV.reason}`, steps);
    steps.push(`[2] Integrity OK  signer: ${addrV.issuerDid}`);

    // 3. Authority — is the signer the trusted index?
    steps.push(`[3] Check index authority`);
    if (addrV.issuerDid !== this.policy.trustedIndex)
      return fail(`AgentAddr signed by untrusted index: ${addrV.issuerDid}`, steps);
    steps.push(`[3] Authority OK`);

    // 4. Fetch AgentFacts
    steps.push(`[4] Fetch AgentFacts from ${addr.primary_facts_url}`);
    const facts = this.factsStore.fetch(addr.primary_facts_url);
    if (!facts) return fail(`AgentFacts not found at: ${addr.primary_facts_url}`, steps, addr);
    steps.push(`[4] AgentFacts fetched`);

    // 5. Integrity — verify AgentFacts proof
    steps.push(`[5] Verify AgentFacts proof (integrity)`);
    const factsV = await verifyProof(facts);
    if (!factsV.valid) return fail(`AgentFacts proof invalid: ${factsV.reason}`, steps, addr);
    steps.push(`[5] Integrity OK  issuer: ${factsV.issuerDid}`);

    // 6. Authority — is the issuer in the trusted-issuers allowlist?
    steps.push(`[6] Check issuer authority`);
    if (!this.policy.trustedIssuers.includes(factsV.issuerDid))
      return fail(`AgentFacts from untrusted issuer: ${factsV.issuerDid}`, steps, addr);
    steps.push(`[6] Authority OK`);

    // 7. Name consistency — AgentFacts.agent_name must equal AgentAddr.agent_name (§8.1, §8.4, §8.5)
    steps.push(`[7] Enforce name consistency`);
    if (facts.agent_name !== addr.agent_name)
      return fail(
        `Name mismatch: facts "${facts.agent_name}" != addr "${addr.agent_name}"`,
        steps, addr,
      );
    steps.push(`[7] Name consistency OK`);

    // 8. Select endpoint and simulate call (§8.5 "act")
    const endpoint = facts.endpoints.static?.[0];
    if (!endpoint) return fail('No static endpoints available', steps, addr, facts);
    const authMethods = facts.capabilities.authentication?.methods.join(', ') ?? 'none';
    steps.push(`[8] Endpoint selected: ${endpoint}`);
    steps.push(`[8] Would authenticate via: ${authMethods}`);

    return { ok: true, addr, facts, endpoint, steps };
  }
}

function fail(
  reason: string,
  steps: string[],
  addr?: Secured<AgentAddr>,
  facts?: Secured<AgentFacts>,
): ResolveResult {
  return { ok: false, reason, addr, facts, steps };
}
