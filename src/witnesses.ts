/**
 * witnesses.ts
 *
 * Off-chain witness providers for vulnerable.compact and secure.compact.
 *
 * In Midnight, witness functions supply private inputs to ZK circuits.
 * The circuit uses the witness value in its computation but the value itself
 * is never revealed on-chain — only the proof that the computation is correct.
 *
 * Key difference between the two contracts:
 *   vulnerable.compact  — no witnesses needed; uses built-in ownPublicKey()
 *   secure.compact      — requires localSecretKey() witness from the owner
 */

import { WitnessContext } from '@midnight-ntwrk/compact-runtime';

// ─── Vulnerable contract ──────────────────────────────────────────────────────
// vulnerable.compact uses ownPublicKey(), which is a built-in — not a witness.
// The wallet populates it automatically from the transaction signer's coin key.
// No off-chain state needed.
export type VulnerablePrivateState = Record<string, never>;

export const vulnerableWitnesses = {};

export const createVulnerablePrivateState = (): VulnerablePrivateState => ({});

// ─── Secure contract ──────────────────────────────────────────────────────────
// The private state held locally by the owner — never leaves their machine.
export type VaultPrivateState = {
  readonly secretKey: Uint8Array;
};

// Factory — creates a VaultPrivateState from a raw secret key.
// Always use crypto.getRandomValues to generate the secret key:
//   const sk = crypto.getRandomValues(new Uint8Array(32));
// Math.random() is NOT cryptographically secure and must never be used here.
export const createVaultPrivateState = (
  secretKey: Uint8Array
): VaultPrivateState => ({ secretKey });

// Witness implementations — keyed to match the witness declarations in secure.compact.
export const secureWitnesses = {
  /**
   * localSecretKey
   *
   * Provides the owner's secret key to the ZK circuit at proof-generation time.
   * The circuit uses this value to compute ownerCommitment(sk) and assert it
   * matches the stored vault_owner on the ledger.
   *
   * Returns [updated private state, secret key bytes].
   * Private state is unchanged — we only read the key, never rotate it here.
   */
  localSecretKey: (
    { privateState }: WitnessContext<VaultPrivateState>
  ): [VaultPrivateState, Uint8Array] => [
    privateState,
    privateState.secretKey,
  ],
};
