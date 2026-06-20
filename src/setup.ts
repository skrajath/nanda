// Register two structurally distinct NANDA-native agents.
// TranslationAssistant (text/streaming) and PaymentStatusAssistant (structured-data/batch).
// See NANDA-L1-DESIGN.md §4 and NANDA-L1-PLAN.md §4.

import { randomUUID } from 'crypto';
import type { AgentAddr, AgentFacts } from './types.js';
import type { LeanIndex } from './index-service.js';
import type { FactsStore } from './facts-store.js';

export const AGENT_NAMES = {
  translation: 'urn:agent:nanda:TranslationAssistant',
  payment:     'urn:agent:nanda:PaymentStatusAssistant',
} as const;

export async function setupAgents(index: LeanIndex, factsStore: FactsStore) {
  // ── Agent 1: TranslationAssistant ─────────────────────────────────────────
  const translationFacts: Omit<AgentFacts, 'issuer'> = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://nanda.example/v1'],
    type: ['VerifiableCredential', 'AgentFacts'],
    id: `nanda:${randomUUID()}`,
    agent_name: AGENT_NAMES.translation,
    label: 'Translation Assistant',
    description: 'Translates text between languages with high accuracy.',
    version: '1.2.0',
    provider: { name: 'NANDA Demo', url: 'https://nanda.example' },
    endpoints: {
      static: ['https://agents.nanda.example/translation/v1'],
      adaptive_resolver: 'https://router.nanda.example/translation', // carried, not executed in L1
    },
    capabilities: {
      modalities: ['text'],
      streaming: true,
      batch: true,
      authentication: { methods: ['oauth2'], requiredScopes: ['translate:read'] },
    },
    skills: [
      {
        id: 'translate',
        description: 'Translate text from source to target language.',
        inputModes: ['text'],
        outputModes: ['text'],
        supportedLanguages: ['en', 'es', 'fr', 'de', 'zh', 'ja'],
        latencyBudgetMs: 800,
      },
      {
        id: 'detect-language',
        description: 'Detect the language of input text.',
        inputModes: ['text'],
        outputModes: ['text'],
        supportedLanguages: ['en', 'es', 'fr', 'de', 'zh', 'ja'],
        latencyBudgetMs: 200,
      },
    ],
    ttl: 3600,
  };

  const { url: translationUrl } = await factsStore.host(translationFacts);

  const translationAddr: AgentAddr = {
    agent_id: `nanda:${randomUUID()}`,
    agent_name: AGENT_NAMES.translation,
    primary_facts_url: translationUrl,
    ttl: 3600,
  };
  await index.register(translationAddr);

  // ── Agent 2: PaymentStatusAssistant ───────────────────────────────────────
  const paymentFacts: Omit<AgentFacts, 'issuer'> = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://nanda.example/v1'],
    type: ['VerifiableCredential', 'AgentFacts'],
    id: `nanda:${randomUUID()}`,
    agent_name: AGENT_NAMES.payment,
    label: 'Payment Status Assistant',
    description: 'Queries and reports on payment transaction statuses.',
    version: '2.0.1',
    provider: { name: 'NANDA Demo', url: 'https://nanda.example' },
    endpoints: {
      static: ['https://agents.nanda.example/payments/v2'],
      // no adaptive_resolver — different shape from TranslationAssistant
    },
    capabilities: {
      modalities: ['text', 'structured-data'],
      streaming: false,
      batch: true,
      authentication: {
        methods: ['jwt', 'api-key'],
        requiredScopes: ['payments:read', 'payments:status'],
      },
    },
    skills: [
      {
        id: 'query-transaction',
        description: 'Look up a transaction by ID and return its current status.',
        inputModes: ['text', 'structured-data'],
        outputModes: ['text', 'structured-data'],
        supportedLanguages: ['en'],
        latencyBudgetMs: 300,
      },
      {
        id: 'list-recent',
        description: 'List recent transactions for an account within a time window.',
        inputModes: ['text'],
        outputModes: ['structured-data'],
        latencyBudgetMs: 1500,
      },
    ],
    ttl: 1800,
  };

  const { url: paymentUrl } = await factsStore.host(paymentFacts);

  const paymentAddr: AgentAddr = {
    agent_id: `nanda:${randomUUID()}`,
    agent_name: AGENT_NAMES.payment,
    primary_facts_url: paymentUrl,
    private_facts_url: `facts://private/${AGENT_NAMES.payment}`, // modeled only — L2 privacy path
    ttl: 1800,
  };
  await index.register(paymentAddr);
}
