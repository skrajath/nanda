// Interactive CLI for exploring the NANDA L1 prototype.
// Run with: npm run cli

import * as readline from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import { LeanIndex } from './index-service.js';
import { FactsStore } from './facts-store.js';
import { NandaClient } from './client.js';
import { setupAgents, AGENT_NAMES } from './setup.js';
import type { Secured, AgentAddr, AgentFacts } from './types.js';

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const c = {
  bold:  (s: string) => `\x1b[1m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red:   (s: string) => `\x1b[31m${s}\x1b[0m`,
  cyan:  (s: string) => `\x1b[36m${s}\x1b[0m`,
  dim:   (s: string) => `\x1b[2m${s}\x1b[0m`,
  yellow:(s: string) => `\x1b[33m${s}\x1b[0m`,
};

function hr(char = '─', n = 62) { console.log(char.repeat(n)); }
function section(title: string) {
  console.log();
  hr();
  console.log(c.bold(` ${title}`));
  hr();
}

// ── Bootstrap (shared across all commands) ────────────────────────────────────
async function bootstrap() {
  const index      = await LeanIndex.create();
  const factsStore = await FactsStore.create();
  await setupAgents(index, factsStore);
  const client = new NandaClient(index, factsStore, {
    trustedIndex:   index.did,
    trustedIssuers: [factsStore.did],
  });
  return { index, factsStore, client };
}

// ── Feature handlers ──────────────────────────────────────────────────────────

function showInfrastructure(index: LeanIndex, factsStore: FactsStore) {
  section('Infrastructure — DIDs');
  console.log(c.cyan('Index resolver DID :'), index.did);
  console.log(c.cyan('Facts issuer DID   :'), factsStore.did);
  console.log();
  console.log(c.dim('Each DID is an Ed25519 public key encoded as did:key.'));
  console.log(c.dim('The index resolver signs AgentAddr records; the issuer signs AgentFacts.'));
}

function listAgents(index: LeanIndex, factsStore: FactsStore) {
  section('Registered Agents');
  for (const name of Object.values(AGENT_NAMES)) {
    const addr  = index.resolve(name)!;
    const facts = factsStore.fetch(addr.primary_facts_url)!;
    console.log(c.bold(`\n  ${facts.label}`));
    console.log(`  Name     : ${name}`);
    console.log(`  ID       : ${addr.agent_id}`);
    console.log(`  Endpoint : ${facts.endpoints.static?.[0]}`);
    console.log(`  Auth     : ${facts.capabilities.authentication?.methods.join(', ')}`);
    console.log(`  Skills   : ${facts.skills.map(s => s.id).join(', ')}`);
  }
}

async function resolveAgent(name: string, client: NandaClient) {
  section(`Resolve — ${name}`);
  const result = await client.resolve(name);

  console.log(c.bold('\nResolution steps:'));
  for (const step of result.steps) {
    const icon = step.includes('OK') ? c.green('✓') : c.dim('·');
    console.log(`  ${icon} ${step}`);
  }

  if (result.ok) {
    console.log(c.green('\n  ✓ Resolved successfully\n'));
    console.log(c.bold('  AgentAddr (signed by index):'));
    const { proof: aProof, ...addrFields } = result.addr!;
    console.log('  ', JSON.stringify(addrFields, null, 2).replace(/\n/g, '\n  '));
    console.log(c.dim(`\n  proof.verificationMethod: ${aProof.verificationMethod}`));
    console.log(c.dim(`  proof.proofValue        : ${aProof.proofValue.slice(0, 40)}…`));

    console.log(c.bold('\n  AgentFacts (issuer-signed VC):'));
    const { proof: fProof, ...factsFields } = result.facts!;
    console.log('  ', JSON.stringify(factsFields, null, 2).replace(/\n/g, '\n  '));
    console.log(c.dim(`\n  proof.verificationMethod: ${fProof.verificationMethod}`));
    console.log(c.dim(`  proof.proofValue        : ${fProof.proofValue.slice(0, 40)}…`));

    console.log(c.bold('\n  Action:'));
    console.log(`  Would call   : ${c.cyan(result.endpoint!)}`);
    const auth = result.facts!.capabilities.authentication;
    console.log(`  Auth method  : ${auth?.methods.join(', ')}`);
    if (auth?.requiredScopes) console.log(`  Scopes needed: ${auth.requiredScopes.join(', ')}`);
  } else {
    console.log(c.red(`\n  ✗ Failed: ${result.reason}`));
  }
}

async function tamperTestA(
  index: LeanIndex,
  factsStore: FactsStore,
  client: NandaClient,
) {
  section('Tamper Test A — Capability Edit (breaks AgentFacts issuer signature)');
  console.log('What we do:');
  console.log(c.yellow('  Take the signed AgentFacts for TranslationAssistant'));
  console.log(c.yellow('  Change streaming: true  →  false  (without re-signing)'));
  console.log(c.yellow('  Ask the client to resolve — it should detect the forgery\n'));

  const addr    = index.resolve(AGENT_NAMES.translation)!;
  const facts   = factsStore.fetch(addr.primary_facts_url)! as Secured<AgentFacts>;
  const tampered: Secured<AgentFacts> = {
    ...facts,
    capabilities: { ...facts.capabilities, streaming: false },
  };
  factsStore.injectForTesting(addr.primary_facts_url, tampered);

  const result = await client.resolve(AGENT_NAMES.translation);
  for (const step of result.steps) {
    const icon = step.includes('OK') ? c.green('✓') : c.dim('·');
    console.log(`  ${icon} ${step}`);
  }
  console.log(
    result.ok
      ? c.red('\n  ✗ UNEXPECTED: resolved tampered facts')
      : c.green(`\n  ✓ Attack rejected at step [5] — ${result.reason}`),
  );
  console.log(c.dim('\n  Why: the signature was made over the original document.'));
  console.log(c.dim('  Changing any byte breaks SHA-256(JCS(doc)) → Ed25519 verify fails.'));

  // Restore
  factsStore.injectForTesting(addr.primary_facts_url, facts);
}

async function tamperTestB(
  index: LeanIndex,
  factsStore: FactsStore,
  client: NandaClient,
) {
  section('Tamper Test B — facts_url Swap (breaks AgentAddr index signature)');
  console.log('What we do:');
  console.log(c.yellow('  Take the signed AgentAddr for TranslationAssistant'));
  console.log(c.yellow('  Replace primary_facts_url with PaymentStatusAssistant\'s URL (without re-signing)'));
  console.log(c.yellow('  Ask the client to resolve — it should detect the redirect\n'));

  const addrT = index.resolve(AGENT_NAMES.translation)!;
  const addrP = index.resolve(AGENT_NAMES.payment)!;
  const tampered: Secured<AgentAddr> = {
    ...addrT,
    primary_facts_url: addrP.primary_facts_url,
  };
  index.injectForTesting(AGENT_NAMES.translation, tampered);

  const result = await client.resolve(AGENT_NAMES.translation);
  for (const step of result.steps) {
    const icon = step.includes('OK') ? c.green('✓') : c.dim('·');
    console.log(`  ${icon} ${step}`);
  }
  console.log(
    result.ok
      ? c.red('\n  ✗ UNEXPECTED: resolved swapped AgentAddr')
      : c.green(`\n  ✓ Attack rejected at step [2] — ${result.reason}`),
  );
  console.log(c.dim('\n  Why: facts_url is covered by the index signature.'));
  console.log(c.dim('  Swapping it changes SHA-256(JCS(addr)) → Ed25519 verify fails.'));

  // Restore
  index.injectForTesting(AGENT_NAMES.translation, addrT);
}

function showRawRecord(index: LeanIndex, factsStore: FactsStore, choice: string) {
  section(`Raw signed record — ${choice}`);
  const name = choice === '1' ? AGENT_NAMES.translation : AGENT_NAMES.payment;
  const addr  = index.resolve(name)!;
  const facts = factsStore.fetch(addr.primary_facts_url)!;
  console.log(c.bold('\nAgentAddr (full JSON):'));
  console.log(JSON.stringify(addr, null, 2));
  console.log(c.bold('\nAgentFacts (full JSON):'));
  console.log(JSON.stringify(facts, null, 2));
}

// ── Main menu loop ────────────────────────────────────────────────────────────
async function main() {
  console.clear();
  console.log(c.bold('╔══════════════════════════════════════════╗'));
  console.log(c.bold('║   NANDA Index — Level 1 Interactive CLI  ║'));
  console.log(c.bold('╚══════════════════════════════════════════╝'));
  console.log(c.dim('\nBootstrapping index + facts store…'));

  const { index, factsStore, client } = await bootstrap();
  console.log(c.green('✓ Ready\n'));

  const rl = readline.createInterface({ input, output });

  const menu = `
${c.bold('Choose a feature to explore:')}

  ${c.cyan('1')}  Show infrastructure DIDs
  ${c.cyan('2')}  List registered agents
  ${c.cyan('3')}  Resolve TranslationAssistant  (happy path)
  ${c.cyan('4')}  Resolve PaymentStatusAssistant (happy path)
  ${c.cyan('5')}  Tamper test A — capability edit   (breaks AgentFacts signature)
  ${c.cyan('6')}  Tamper test B — facts_url swap     (breaks AgentAddr signature)
  ${c.cyan('7')}  Show raw signed records (TranslationAssistant)
  ${c.cyan('8')}  Show raw signed records (PaymentStatusAssistant)
  ${c.cyan('9')}  Run full demo (all of the above)
  ${c.cyan('q')}  Quit
`;

  while (true) {
    console.log(menu);
    const choice = (await rl.question('  > ')).trim().toLowerCase();

    switch (choice) {
      case '1': showInfrastructure(index, factsStore); break;
      case '2': listAgents(index, factsStore); break;
      case '3': await resolveAgent(AGENT_NAMES.translation, client); break;
      case '4': await resolveAgent(AGENT_NAMES.payment, client); break;
      case '5': await tamperTestA(index, factsStore, client); break;
      case '6': await tamperTestB(index, factsStore, client); break;
      case '7': showRawRecord(index, factsStore, '1'); break;
      case '8': showRawRecord(index, factsStore, '2'); break;
      case '9':
        showInfrastructure(index, factsStore);
        listAgents(index, factsStore);
        await resolveAgent(AGENT_NAMES.translation, client);
        await resolveAgent(AGENT_NAMES.payment, client);
        await tamperTestA(index, factsStore, client);
        await tamperTestB(index, factsStore, client);
        break;
      case 'q':
      case 'quit':
      case 'exit':
        console.log('\nBye.\n');
        rl.close();
        process.exit(0);
      default:
        console.log(c.dim('  Unrecognised — enter a number 1–9 or q'));
    }

    await rl.question(c.dim('\n  Press Enter to return to menu…'));
    console.clear();
  }
}

main().catch(err => { console.error(err); process.exit(1); });
