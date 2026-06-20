# NANDA Index — Level 1 Implementation Plan

Reference paper: `2507.14263v1.pdf` — *Beyond DNS: Unlocking the Internet of AI
Agents via the NANDA Index and Verified AgentFacts* (Project NANDA, v0.3 draft).

This plan covers a working, end-to-end Level 1 prototype of the index
resolution flow, preceded by a concept deep-dive so each implementation
decision is grounded rather than arbitrary.

---

## 1. Level 1 scope & acceptance criteria

Make it work end-to-end:

- Register **at least two** agents.
- A client resolves an agent **by name** and receives something it can
  **verify and act on**.
- The paper's core flow — `name -> index -> AgentAddr -> AgentFacts` — is
  **visible in the code**, not buried.
- The client can **detect tampering**.

Out of scope for L1 (these are Level 2): mixing registration types
(NANDA-native vs enterprise-routed vs DID-routed).

---

## 2. Key design decision — the verification approach

The spec deliberately leaves the verification mechanism open ("part of the
exercise"). The spectrum:

- **Bare signed JSON / JWS** — floor. Tamper-evident, trivial, but discards
  the "issuer-signed claims + forward-compatible schema" property.
- **W3C VC 2.0 Data Integrity, `eddsa-jcs-2022` cryptosuite** — Ed25519 over
  RFC 8785 (JCS) canonicalised JSON. A real, registered VC cryptosuite, but
  JCS sidesteps JSON-LD/RDF canonicalisation. **<- our choice.**
- **Full JSON-LD VC, `eddsa-rdfc-2022`** — ceiling. Most faithful, but drags
  in RDF dataset canonicalisation + DID-document resolution; effort would not
  change what the L1 demo proves.

**Decision:** `eddsa-jcs-2022` Data Integrity proofs, with `did:key` issuers.
One signer/verifier serves both the AgentAddr (signed by the index resolver)
and the AgentFacts (signed by a credential issuer). Clean upgrade path into
Level 2 issuer-trust and revocation.

---

## 3. Architecture — module decomposition

Each module maps to one box in the paper's architecture so the tier
separation is physical, not just conceptual.

- `types.ts` — data model: `AgentAddr`, `AgentFacts`, `DataIntegrityProof`.
- `crypto.ts` — verification primitive: Ed25519 keygen, `did:key`
  encode/decode, JCS canonicalisation, `addProof` / `verifyProof`
  (the `eddsa-jcs-2022` cryptosuite).
- `index-service.ts` — the lean index. `register()` signs + stores an
  AgentAddr; `resolve(name)` returns the signed record. Pointers only —
  never endpoints or capabilities.
- `facts-store.ts` — AgentFacts hosting, a separate component so the
  index->facts decoupling is enforced by the boundary.
- `client.ts` — resolution client + trust policy (trusted index key +
  issuer allowlist). Verifies each hop; refuses to proceed on failure.
- `setup.ts` — issues keys and registers the two agents.
- `demo.ts` — end-to-end runner: happy-path resolution x2, then tamper tests.

## 4. The two agents (both NANDA-native)

- `TranslationAssistant` — the paper's running example.
- `PaymentStatusAssistant` — structurally different capabilities/skills, with
  a `private_facts_url` populated as a pointer (resolving via the privacy path
  is Level 2). Different shapes make "resolve twice" meaningful.
