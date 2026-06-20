# NANDA Index — Level 1 prototype

End-to-end demonstration of the NANDA resolution flow:
`name → index → AgentAddr → AgentFacts`, with W3C Verifiable Credential
(`eddsa-jcs-2022`) tamper detection.

Design and rationale live one level up: `../NANDA-L1-DESIGN.md` (architecture +
decision log 8.1–8.5) and `../NANDA-L1-PLAN.md` (build plan).

## What it proves (L1 acceptance)

- Two NANDA-native agents are registered.
- A client resolves each by name, walks the full path through metadata
  retrieval, and verifies what it gets back.
- Tamper test A (capability edit) breaks the issuer's proof; tamper test B
  (facts_url swap) breaks the index resolver's proof. Both are rejected.

## Build order

1. `src/crypto.ts` — Ed25519, did:key encode/decode, JCS canonicalisation,
   `addProof` / `verifyProof` (the eddsa-jcs-2022 cryptosuite), and a pluggable
   `didToPublicKey()` seam.
2. `src/types.ts` — data model (already scaffolded).
3. `src/index-service.ts` — `LeanIndex`: `register()` signs + stores an
   AgentAddr; `resolve(name)` returns it. Pointers only.
4. `src/facts-store.ts` — `FactsStore`: `host()` signs an AgentFacts with an
   issuer key; `fetch(url)` returns it. Does not verify (client verifies).
5. `src/client.ts` — `resolve()` pipeline + `TrustPolicy`; integrity then
   authority, hard-fail with a reason, name-consistency check, simulated act.
6. `src/setup.ts` — two agents (distinct shapes); issuer key ≠ resolver key.
7. `src/demo.ts` — resolve both end-to-end, then run tamper tests A and B.

## Run

```
npm install
npm run demo
```

## Scope (L1 only — see design doc §7)

In: name resolution, AgentAddr + AgentFacts records, two independent
signatures, tamper detection.

Out (Level 2): privacy-path resolution, adaptive routing execution, TTL-driven
caching, revocation / VC-Status, federated cross-zone issuer trust, and mixed
registration types (enterprise-routed, DID-routed).
