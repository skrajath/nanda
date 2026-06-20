// Shared data model for the NANDA Level 1 prototype.
//
// Two records mirror the paper:
//   - AgentAddr  : the lean index record (static identity + pointers), signed by the index resolver.
//   - AgentFacts : the metadata document (capabilities, endpoints), signed as a Verifiable Credential.
// Both carry the same kind of proof, so one verifier handles both. See NANDA-L1-DESIGN.md (sections
// 4-6) and the decision log (8.1-8.5) for the rationale behind every field and choice here.

/**
 * A W3C VC 2.0 Data Integrity proof using the eddsa-jcs-2022 cryptosuite.
 * (Ed25519 signature over RFC 8785 / JCS-canonicalised JSON.) See 8.3.
 */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: "eddsa-jcs-2022";
  created: string; // ISO 8601 timestamp
  verificationMethod: string; // did:key URL of the signing key
  proofPurpose: "assertionMethod";
  proofValue: string; // multibase(base58btc) Ed25519 signature, "z" prefix
}

/** Anything that has been signed carries a proof. */
export type Secured<T> = T & { proof: DataIntegrityProof };

// ---- Anchor tier: the lean index record (see 8.2) ---------------------------

/**
 * The lean index record. Holds only static identity + pointers (no live
 * endpoints, no capabilities). Signed by the *index resolver*.
 */
export interface AgentAddr {
  agent_id: string; // stable machine id, e.g. "nanda:<uuid v4>"
  agent_name: string; // URN lookup key, e.g. "urn:agent:salesforce:TranslationAssistant"
  primary_facts_url: string; // pointer to the AgentFacts (agent domain)
  private_facts_url?: string; // optional privacy-preserving pointer (modeled only in L1)
  adaptive_resolver_url?: string; // optional dynamic-routing pointer (modeled only in L1)
  ttl: number; // seconds the AgentAddr may be cached
}

// ---- Metadata tier: AgentFacts (see 8.4) ------------------------------------

/** TTL-scoped endpoint sets. L1 resolves `static`; the rest are carried only. */
export interface AgentEndpoints {
  static?: string[]; // 1-6 h
  rotating?: string[]; // 5-15 min (L2)
  adaptive_resolver?: string; // programmable routing (L2)
}

/** Capability descriptor (subset of the appendix schema). */
export interface AgentCapabilities {
  modalities?: string[];
  streaming?: boolean;
  batch?: boolean;
  authentication?: {
    methods: string[]; // e.g. ["oauth2", "jwt"] - tells the client HOW to auth
    requiredScopes?: string[];
  };
}

/** One skill entry (green A2A fields + a couple of blue NANDA fields). */
export interface AgentSkill {
  id: string;
  description: string;
  inputModes?: string[];
  outputModes?: string[];
  supportedLanguages?: string[]; // blue (NANDA)
  latencyBudgetMs?: number; // blue (NANDA)
}

/**
 * The AgentFacts metadata document. JSON-LD *shaped* and signed as a
 * Verifiable Credential (the @context is signed but not RDF-processed in L1).
 * Signed by a *credential issuer*. `agent_name` must equal the AgentAddr
 * that pointed here.
 */
export interface AgentFacts {
  "@context": string[];
  type: string[]; // ["VerifiableCredential", "AgentFacts"]
  issuer: string; // did:key of the issuer
  id: string;
  agent_name: string;
  label: string;
  description: string;
  version: string;
  provider: { name: string; url?: string; did?: string };
  endpoints: AgentEndpoints;
  capabilities: AgentCapabilities;
  skills: AgentSkill[];
  ttl: number;
}
