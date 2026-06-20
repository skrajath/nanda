# NANDA Index — Level 1 Prototype

End-to-end implementation of the NANDA resolution flow:

```
agent name  →  LeanIndex  →  AgentAddr  →  FactsStore  →  AgentFacts  →  act
                 (signed)                    (VC-signed)
```

Every record is cryptographically signed. The client verifies every hop itself —
it never trusts the transport. Tamper anything in the chain and the client rejects
it with a precise reason before acting.

Design rationale and decision log live one level up:
- `../NANDA-L1-DESIGN.md` — architecture, component map, decisions 8.1–8.5
- `../NANDA-L1-PLAN.md` — build plan and scope

---

## Quick start

```bash
cd nanda-l1
npm install

npm run demo   # automated run — resolves both agents, runs tamper tests, exits
npm run cli    # interactive menu — explore each feature one at a time
```

---

## File structure

```
nanda-l1/
├── src/
│   ├── types.ts          data model — AgentAddr, AgentFacts, DataIntegrityProof
│   ├── crypto.ts         Ed25519 + eddsa-jcs-2022 — addProof / verifyProof
│   ├── index-service.ts  LeanIndex — register and resolve AgentAddr records
│   ├── facts-store.ts    FactsStore — host and fetch AgentFacts documents
│   ├── client.ts         NandaClient — full resolution pipeline + trust policy
│   ├── setup.ts          register two agents (TranslationAssistant, PaymentStatusAssistant)
│   ├── demo.ts           automated end-to-end runner
│   └── cli.ts            interactive menu for exploring all features
├── package.json
└── tsconfig.json
```

---

## What each file does

### `types.ts` — data model

Defines three interfaces that map directly to the paper's records:

**`DataIntegrityProof`** — the W3C VC 2.0 Data Integrity proof object embedded in every signed record:

```ts
{
  type:               "DataIntegrityProof"
  cryptosuite:        "eddsa-jcs-2022"
  created:            "2024-01-01T00:00:00.000Z"   // ISO 8601
  verificationMethod: "did:key:z6Mk...#z6Mk..."     // signing key
  proofPurpose:       "assertionMethod"
  proofValue:         "z3J9..."                     // multibase base58btc signature
}
```

**`AgentAddr`** — the lean index record. Holds identity + pointers only. No endpoints, no capabilities. Signed by the index resolver.

```ts
{
  agent_id:           "nanda:<uuid v4>"             // stable machine identity
  agent_name:         "urn:agent:nanda:TranslationAssistant"  // URN lookup key
  primary_facts_url:  "facts://urn:agent:nanda:TranslationAssistant"
  private_facts_url?: "facts://private/..."         // L2 privacy path (pointer only)
  ttl:                3600                          // seconds (carried, not enforced in L1)
  proof:              DataIntegrityProof
}
```

**`AgentFacts`** — the metadata document, shaped as a W3C Verifiable Credential. Signed by a credential issuer (separate key from the index resolver).

```ts
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://nanda.example/v1"],
  type:       ["VerifiableCredential", "AgentFacts"],
  issuer:     "did:key:z6Mk..."           // issuer DID
  id:         "nanda:<uuid v4>"
  agent_name: "urn:agent:nanda:TranslationAssistant"   // must match AgentAddr
  label:      "Translation Assistant"
  endpoints:  { static: ["https://..."], adaptive_resolver: "https://..." }
  capabilities: { modalities, streaming, batch, authentication }
  skills:     [{ id, description, inputModes, outputModes, supportedLanguages, latencyBudgetMs }]
  ttl:        3600
  proof:      DataIntegrityProof
}
```

`Secured<T>` is a utility type: `T & { proof: DataIntegrityProof }` — used throughout to distinguish signed from unsigned values.

---

### `crypto.ts` — cryptographic primitives

Implements the `eddsa-jcs-2022` Data Integrity cryptosuite over Ed25519.

**Key generation**

```ts
const keypair = await generateKeyPair();
// keypair.did                → "did:key:z6Mk..."
// keypair.verificationMethod → "did:key:z6Mk...#z6Mk..."
// keypair.privateKey         → Uint8Array (32 bytes)
// keypair.publicKey          → Uint8Array (32 bytes)
```

The `did:key` identifier is built by prepending the Ed25519 multicodec prefix (`0xed 0x01`) to the raw public key bytes, then encoding the whole thing as multibase base58btc (leading `z`).

**`addProof(document, keypair)`** — signs a document

Algorithm (`eddsa-jcs-2022`):
1. Build a `proofConfig` object (all proof fields except `proofValue`)
2. `configHash = SHA-256(JCS(proofConfig))`
3. `docHash    = SHA-256(JCS(document))`
4. `hashData   = configHash || docHash`  (64 bytes)
5. Sign `hashData` with Ed25519 → encode as multibase base58btc → `proofValue`
6. Return `{ ...document, proof: { ...proofConfig, proofValue } }`

**`verifyProof(secured)`** — verifies a signed record

1. Separate `proof` from the rest of the document
2. Extract `proofValue`, reconstruct `proofConfig` (without `proofValue`)
3. Rebuild `hashData` identically
4. Decode `proofValue` from multibase base58btc → verify Ed25519 signature
5. Return `{ valid: boolean, issuerDid: string, reason? }`

Returns the `issuerDid` separately so the client can make a trust-policy decision after the integrity check (valid signature ≠ trusted issuer).

**`didToPublicKey(verificationMethod)`** — decodes a `did:key` to raw public key bytes. Accepts both `did:key:z...` and `did:key:z...#z...` (verification method URL). Strips the multicodec prefix and validates it's Ed25519 (`0xed 0x01`).

Dependencies: `@noble/ed25519`, `@noble/hashes/sha256`, `@scure/base` (base58), `canonicalize` (JCS / RFC 8785).

---

### `index-service.ts` — LeanIndex

An in-memory index keyed by `agent_name`. Owns the index resolver keypair; every `AgentAddr` it stores is signed with that key.

```ts
const index = await LeanIndex.create();   // generates resolver keypair
index.did                                 // the resolver's DID (used in trust policy)

await index.register(agentAddr);          // signs agentAddr, stores under agent_name
index.resolve("urn:agent:nanda:...")      // returns Secured<AgentAddr> or undefined
index.injectForTesting(name, record)      // test seam: insert without re-signing
```

The index never sees AgentFacts content. It stores only pointers (`primary_facts_url`, etc.) — the tier decoupling is enforced by the type system: `AgentAddr` has no endpoint or capability fields.

---

### `facts-store.ts` — FactsStore

An in-memory store keyed by URL string. Owns a separate issuer keypair — distinct from the index resolver key, which is the whole point (two signers, two attack classes).

```ts
const factsStore = await FactsStore.create();   // generates issuer keypair
factsStore.did                                  // the issuer's DID (used in trust policy)

const { url } = await factsStore.host(facts);   // sets issuer field, signs, stores
factsStore.fetch(url)                           // returns Secured<AgentFacts> or undefined
factsStore.injectForTesting(url, record)        // test seam: insert without re-signing
```

`host()` takes `Omit<AgentFacts, 'issuer'>` — the caller does not set the issuer; the store sets it to its own DID before signing. This ensures the issuer field in the signed document always matches the key that signed it.

---

### `client.ts` — NandaClient + TrustPolicy

The only active party at runtime. Orchestrates the full chain; every other component is a passive store.

**Construction**

```ts
const client = new NandaClient(index, factsStore, {
  trustedIndex:   index.did,          // only accept AgentAddr signed by this DID
  trustedIssuers: [factsStore.did],   // only accept AgentFacts from these DIDs
});
```

**`client.resolve(agentName)`** — the single public entry point

Returns a `ResolveResult`:

```ts
{
  ok:       boolean
  reason?:  string                  // present on failure — which step, why
  addr?:    Secured<AgentAddr>      // present on success
  facts?:   Secured<AgentFacts>     // present on success
  endpoint?: string                 // first static endpoint, ready to call
  steps:    string[]                // full trace of every step taken
}
```

**8-step pipeline** (hard-fail on any step — no fallbacks in L1):

| Step | Action | What it catches |
|------|--------|----------------|
| 1 | Lookup `agentName` in index | Agent not registered |
| 2 | `verifyProof(addr)` — integrity | AgentAddr tampered after signing |
| 3 | `addr.issuerDid === policy.trustedIndex` — authority | AgentAddr signed by wrong key |
| 4 | Fetch `addr.primary_facts_url` from facts store | URL not found |
| 5 | `verifyProof(facts)` — integrity | AgentFacts tampered after signing |
| 6 | `facts.issuerDid in policy.trustedIssuers` — authority | AgentFacts from untrusted issuer |
| 7 | `facts.agent_name === addr.agent_name` — name consistency | Facts document stapled to wrong name |
| 8 | Select `facts.endpoints.static[0]`, read auth method — act | No static endpoint available |

Integrity always runs before authority. A tampered record never reaches the policy check.

---

### `setup.ts` — agent registration

Registers two structurally distinct agents to make "resolve twice" meaningful:

| | TranslationAssistant | PaymentStatusAssistant |
|---|---|---|
| Modalities | `text` | `text`, `structured-data` |
| Streaming | `true` | `false` |
| Auth | `oauth2` | `jwt`, `api-key` |
| Scopes | `translate:read` | `payments:read`, `payments:status` |
| Skills | translate, detect-language | query-transaction, list-recent |
| Adaptive resolver | yes (carried, L2) | no |
| Private facts URL | no | yes (pointer only, L2) |
| TTL | 3600 s | 1800 s |

Both `agent_id` values are `nanda:<uuid v4>`, generated fresh per run. The `issuer` field in each `AgentFacts` is set by `FactsStore.host()`, not by `setup.ts`.

---

### `demo.ts` — automated runner

Runs everything in sequence and exits. Useful for CI or a quick sanity check.

1. Bootstrap index + facts store, register both agents
2. Resolve `TranslationAssistant` — happy path
3. Resolve `PaymentStatusAssistant` — happy path
4. Tamper test A — capability edit
5. Tamper test B — facts_url swap
6. Print pass/fail summary, exit with code 1 on any unexpected result

---

### `cli.ts` — interactive menu

```
npm run cli
```

Menu:

| Key | Feature |
|-----|---------|
| 1 | Show both DIDs (index resolver + issuer) |
| 2 | List registered agents with endpoint, auth, and skills |
| 3 | Resolve TranslationAssistant — full step trace + raw records |
| 4 | Resolve PaymentStatusAssistant — full step trace + raw records |
| 5 | Tamper test A — mutate capability, watch step [5] reject it |
| 6 | Tamper test B — swap facts_url, watch step [2] reject it |
| 7 | Full raw JSON for TranslationAssistant (AgentAddr + AgentFacts with proof) |
| 8 | Full raw JSON for PaymentStatusAssistant |
| 9 | Run everything in sequence |
| q | Quit |

---

## Data flow — end to end

```
setup.ts
  │
  ├─ factsStore.host(translationFacts)
  │     ├─ sets issuer = factsStore.did
  │     ├─ addProof(facts, issuerKeypair)   ← SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(facts))
  │     └─ stores at "facts://urn:agent:nanda:TranslationAssistant"
  │
  └─ index.register(translationAddr)
        ├─ addProof(addr, resolverKeypair)  ← same algorithm, different key
        └─ stores under "urn:agent:nanda:TranslationAssistant"

client.resolve("urn:agent:nanda:TranslationAssistant")
  │
  ├─ [1] index.resolve(name)               → Secured<AgentAddr>
  ├─ [2] verifyProof(addr)                 → { valid, issuerDid }
  ├─ [3] issuerDid === policy.trustedIndex → authority check
  ├─ [4] factsStore.fetch(addr.primary_facts_url) → Secured<AgentFacts>
  ├─ [5] verifyProof(facts)                → { valid, issuerDid }
  ├─ [6] issuerDid in policy.trustedIssuers → authority check
  ├─ [7] facts.agent_name === addr.agent_name → name consistency
  └─ [8] pick facts.endpoints.static[0]   → endpoint to call
```

---

## How tamper scenarios are handled

### Tamper test A — capability edit (breaks AgentFacts signature)

**Attack:** after `factsStore.host()` signs the `AgentFacts`, an attacker modifies a field (e.g. `streaming: true → false`) and puts the modified document back in the store.

**Detection:** step [5] — `verifyProof(facts)`.

The signature was made over `SHA-256(JCS(originalFacts))`. The modified document produces a different hash. Ed25519 verification fails. The client stops at step [5] and never reaches the trust-policy or name-consistency checks.

**Why a single signature cannot cover both record types:** if there were only one signature (say, only the index signs everything), an attacker could edit the AgentFacts freely because the index only signed the AgentAddr. The separate issuer signature on `AgentFacts` is what closes this gap.

### Tamper test B — facts_url swap (breaks AgentAddr signature)

**Attack:** after `index.register()` signs the `AgentAddr`, an attacker replaces `primary_facts_url` with a different agent's facts URL. When the client follows it, it fetches a legitimately-signed `AgentFacts` for a different agent.

**Detection:** step [2] — `verifyProof(addr)`.

The `primary_facts_url` is part of the `AgentAddr` document that was signed. Changing it changes `SHA-256(JCS(addr))`. Ed25519 verification fails immediately. The client never fetches the redirected facts.

Note: even if step [2] somehow passed (it doesn't), step [7] would catch it — the swapped facts document has `agent_name = "urn:agent:nanda:PaymentStatusAssistant"` while the `AgentAddr` says `"urn:agent:nanda:TranslationAssistant"`.

---

## Cryptosuite — eddsa-jcs-2022 in detail

The `eddsa-jcs-2022` cryptosuite is a registered W3C VC Data Integrity cryptosuite. It uses JCS (RFC 8785) for canonicalisation instead of RDF dataset canonicalisation, which means no JSON-LD context fetching or blank-node normalisation.

**Signing a document `D` with keypair `K`:**

```
proofConfig = { type, cryptosuite, created, verificationMethod, proofPurpose }
hashData    = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(D))   // 64 bytes
signature   = Ed25519.sign(hashData, K.privateKey)
proofValue  = "z" + base58btc(signature)
```

**Verifying `{ ...D, proof }`:**

```
proofConfig = proof without proofValue
hashData    = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(D))
publicKey   = didToPublicKey(proof.verificationMethod)
valid       = Ed25519.verify(base58btc.decode(proof.proofValue[1:]), hashData, publicKey)
```

The `did:key` identifier encodes the public key directly:

```
publicKeyBytes  → prepend [0xed, 0x01] (Ed25519 multicodec)
               → base58btc encode
               → prepend "z" (multibase prefix)
               → prepend "did:key:"
```

Decoding is the exact reverse. No network lookup needed — the key is self-contained in the identifier.

---

## L1 scope boundary

**In scope (this prototype):**
- Name resolution via URN
- AgentAddr (lean index record, signed by resolver)
- AgentFacts (VC-shaped metadata, signed by issuer)
- Two independent Ed25519 signatures covering two attack classes
- Trust policy: flat allowlist of trusted index DID + trusted issuer DIDs
- Name consistency enforcement
- Simulated act (endpoint selection + auth method display)

**Deferred to Level 2:**
- Privacy-path resolution (`private_facts_url`)
- Adaptive resolver execution
- TTL-driven caching
- Credential revocation / VC-Status
- Federated cross-zone issuer trust
- Mixed registration types (enterprise-routed, DID-routed)
- `did:web` / `did:webvh` issuer resolution (pluggable seam exists in `didToPublicKey`)
