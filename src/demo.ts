// End-to-end demo: happy-path resolution x2, then tamper test A and B.
// Run with: npm run demo

import { LeanIndex } from './index-service.js';
import { FactsStore } from './facts-store.js';
import { NandaClient } from './client.js';
import { setupAgents, AGENT_NAMES } from './setup.js';
import type { Secured, AgentAddr, AgentFacts } from './types.js';

const PASS = '\x1b[32m✓\x1b[0m';
const FAIL = '\x1b[31m✗\x1b[0m';

function header(title: string) {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(` ${title}`);
  console.log('─'.repeat(60));
}

async function main() {
  console.log('\n╔══════════════════════════════════════╗');
  console.log('║  NANDA Index — Level 1 Prototype     ║');
  console.log('╚══════════════════════════════════════╝');

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  const index      = await LeanIndex.create();
  const factsStore = await FactsStore.create();

  await setupAgents(index, factsStore);

  console.log(`\nIndex resolver DID : ${index.did}`);
  console.log(`Facts issuer DID   : ${factsStore.did}`);

  const client = new NandaClient(index, factsStore, {
    trustedIndex:   index.did,
    trustedIssuers: [factsStore.did],
  });

  // ── Happy path ─────────────────────────────────────────────────────────────
  for (const name of Object.values(AGENT_NAMES)) {
    header(`Happy path — ${name}`);
    const result = await client.resolve(name);
    for (const step of result.steps) console.log(`  ${step}`);
    if (result.ok) {
      console.log(`\n  ${PASS} Resolved`);
      console.log(`     Endpoint : ${result.endpoint}`);
      console.log(`     Skills   : ${result.facts!.skills.map(s => s.id).join(', ')}`);
    } else {
      console.log(`\n  ${FAIL} UNEXPECTED FAILURE: ${result.reason}`);
      process.exitCode = 1;
    }
  }

  // ── Tamper test A: capability edit (breaks AgentFacts issuer signature) ────
  header('Tamper test A — capability edit (AgentFacts)');
  console.log('  Mutating streaming:true -> false inside the signed AgentFacts…\n');

  const addrA   = index.resolve(AGENT_NAMES.translation)!;
  const factsA  = factsStore.fetch(addrA.primary_facts_url)! as Secured<AgentFacts>;
  const tamperedA: Secured<AgentFacts> = {
    ...factsA,
    capabilities: { ...factsA.capabilities, streaming: false }, // modify after signing
  };
  factsStore.injectForTesting(addrA.primary_facts_url, tamperedA);

  const resultA = await client.resolve(AGENT_NAMES.translation);
  for (const step of resultA.steps) console.log(`  ${step}`);
  console.log(
    resultA.ok
      ? `\n  ${FAIL} UNEXPECTED: resolved tampered AgentFacts`
      : `\n  ${PASS} Rejected — ${resultA.reason}`,
  );
  if (resultA.ok) process.exitCode = 1;

  // Restore
  factsStore.injectForTesting(addrA.primary_facts_url, factsA);

  // ── Tamper test B: facts_url swap (breaks AgentAddr index signature) ───────
  header('Tamper test B — facts_url swap (AgentAddr)');
  console.log('  Pointing TranslationAssistant\'s primary_facts_url at PaymentStatusAssistant\'s facts…\n');

  const addrTranslation = index.resolve(AGENT_NAMES.translation)!;
  const addrPayment     = index.resolve(AGENT_NAMES.payment)!;
  const tamperedB: Secured<AgentAddr> = {
    ...addrTranslation,
    primary_facts_url: addrPayment.primary_facts_url, // redirect after signing
  };
  index.injectForTesting(AGENT_NAMES.translation, tamperedB);

  const resultB = await client.resolve(AGENT_NAMES.translation);
  for (const step of resultB.steps) console.log(`  ${step}`);
  console.log(
    resultB.ok
      ? `\n  ${FAIL} UNEXPECTED: resolved swapped AgentAddr`
      : `\n  ${PASS} Rejected — ${resultB.reason}`,
  );
  if (resultB.ok) process.exitCode = 1;

  // ── Summary ────────────────────────────────────────────────────────────────
  console.log('\n' + '═'.repeat(60));
  const ok = !process.exitCode;
  console.log(ok
    ? `${PASS} All checks passed — two agents resolved, both tamper tests rejected.`
    : `${FAIL} One or more checks failed.`);
  console.log('═'.repeat(60) + '\n');
}

main().catch(err => { console.error(err); process.exit(1); });
