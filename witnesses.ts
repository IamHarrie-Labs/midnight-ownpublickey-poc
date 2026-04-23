/**
 * witnesses.ts
 *
 * Off-chain witness provider for secure.compact.
 *
 * In Midnight, witness functions supply private inputs to ZK circuits.
 * The circuit uses the witness value in its computation but the value itself
 * is never revealed on-chain — only the proof that the computation is correct.
 *
 * For secure.compact, the only private state is the owner's secret key.
 * The circuit hashes it with persistentHash to derive the owner commitment.
 * The witness just hands the secret key to the circuit at proof-generation time.
 */

import { WitnessContext } from "@midnight-ntwrk/compact-runtime";

// The private state held locally by the owner — never leaves their machine.
export type VaultPrivateState = {
  readonly secretKey: Uint8Array;
};

// Factory — creates a VaultPrivateState from a raw secret key.
// In production, generate this key once and store it securely.
// Example: crypto.getRandomValues(new Uint8Array(32))
export const createVaultPrivateState = (
  secretKey: Uint8Array
): VaultPrivateState => ({
  secretKey,
});

// Witness implementations — keyed to match the witness declarations in secure.compact.
export const witnesses = {
  /**
   * localSecretKey
   *
   * Provides the owner's secret key to the ZK circuit at proof-generation time.
   * The circuit uses this value to compute ownerCommitment(sk) and assert it
   * matches the stored vault_owner on the ledger.
   *
   * Returns a tuple of [updated private state, secret key bytes].
   * Private state is unchanged — we only read the key, never rotate it here.
   */
  localSecretKey: (
    { privateState }: WitnessContext<VaultPrivateState>
  ): [VaultPrivateState, Uint8Array] => [
    privateState,
    privateState.secretKey,
  ],
};
