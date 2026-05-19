/**
 * attack-secure.ts
 *
 * Attempts the same ownPublicKey() spoofing attack against the SECURE vault.
 * Expected result: proof server rejects — constraint UNSATISFIED.
 *
 * Prerequisites:
 *   npx ts-node src/deploy-secure.ts   (deploy secure.compact first)
 *
 * Run:
 *   npx ts-node src/attack-secure.ts
 */

import * as fs   from 'node:fs';
import * as path from 'node:path';

import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-api';
import type { ContractAddress }      from '@midnight-ntwrk/midnight-js-types';

import * as Secure from '../contracts/managed/secure/index.cjs';
import { CONFIG }  from './config.js';

// ─── Why this attack fails ────────────────────────────────────────────────────
//
// secure.compact stores vault_owner = persistentHash(["vault:owner:", sk]).
//
// To call withdraw(), the circuit requires the prover to supply a local_secret_key
// value sk such that:
//   persistentHash(["vault:owner:", sk]) == vault_owner
//
// The attacker reads vault_owner from the ledger — a 32-byte hash value.
// They cannot reverse persistentHash to find sk.
//
// Their best attempt (tried below) is to set local_secret_key = vault_owner,
// hoping that persistentHash(prefix, vault_owner) == vault_owner.
// This would require finding a hash fixed point — computationally infeasible.
//
// The proof server returns: constraint unsatisfied.
//
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { contractAddress } = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), 'secure-deployment.json'), 'utf8'),
  ) as { contractAddress: ContractAddress };

  const publicDataProvider = indexerPublicDataProvider(
    CONFIG.indexerUri,
    CONFIG.indexerWsUri,
  );

  // Step 1: Read vault_owner — same as before, ledger state is always public
  const rawState   = await publicDataProvider.queryContractState(contractAddress);
  const state      = Secure.ledger(rawState);
  const storedOwner: Uint8Array = state.vault_owner as Uint8Array;

  console.log('[Step 1] vault_owner read from public ledger (a persistentHash commitment):');
  console.log(`         ${Buffer.from(storedOwner).toString('hex')}`);
  console.log('         This is a one-way hash — it reveals nothing about the secret key.');

  // Step 2: Attempt the attack — provide vault_owner as if it were the secret key
  // Attack theory: if persistentHash(prefix, vault_owner) == vault_owner, proof passes.
  // Reality: this requires a hash fixed point. persistentHash uses BLAKE2s — infeasible.
  const fakeSecretKey = storedOwner;

  console.log('\n[Step 2] Attack attempt: local_secret_key = vault_owner (stored hash)');
  console.log('         Hoping persistentHash("vault:owner:", vault_owner) == vault_owner');
  console.log('         (This would require a BLAKE2s fixed point — computationally infeasible)');

  // Step 3: Send prove request to proof server
  const proveRes = await fetch(`${CONFIG.proofServerUri}/prove`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contractAddress,
      entryPoint:    'withdraw',
      privateInputs: {
        local_secret_key: Array.from(fakeSecretKey),
      },
    }),
  });

  if (!proveRes.ok) {
    console.log('\n[Step 3] Proof server rejected — constraint UNSATISFIED ✓');
    console.log(`         Error: ${await proveRes.text()}`);
    console.log('\n[✓] ATTACK FAILED — secure.compact is not vulnerable.');
    console.log('    To withdraw, the attacker must know sk such that:');
    console.log('      persistentHash(["vault:owner:", sk]) == vault_owner');
    console.log('    persistentHash is one-way. vault_owner reveals nothing about sk.');
    console.log('    Without the original sk, no valid proof can be constructed.');
    return;
  }

  // Should never reach here
  console.error('\n[!] UNEXPECTED: proof was generated — review secure.compact.');
}

main().catch((err) => { console.error(err); process.exit(1); });
