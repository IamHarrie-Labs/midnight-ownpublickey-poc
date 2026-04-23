# ownPublicKey() Access Control Vulnerability — Proof of Concept

Companion code for the tutorial:
**[The Zero-Knowledge Trap: Why ownPublicKey() Cannot Prove Identity in Compact](https://dev.to/iamharrie/the-zero-knowledge-trap-why-ownpublickey-cannot-prove-identity-in-compact-169i)**

Submitted as part of the [Midnight Eclipse Content Bounty Program](https://forum.midnight.network/t/midnight-content-bounty-program-eclipse/1148) — Issue [#295](https://github.com/midnightntwrk/contributor-hub/issues/295).

---

## What This Repo Shows

In Compact, `ownPublicKey()` compiles to an **unconstrained `private_input`** in the ZK circuit. A prover can set it to any value — including the stored owner key read from public ledger state — without knowing any secret key.

This repo contains two contracts that demonstrate the problem and the fix side by side.

---

## Files

| File | Description |
|---|---|
| `vulnerable.compact` | Uses `ownPublicKey()` for access control — **bypassable by any attacker** |
| `secure.compact` | Uses `witness localSecretKey()` + `persistentHash` commitment — **cryptographically sound** |
| `witnesses.ts` | Off-chain witness provider for `secure.compact` |

---

## The Vulnerability

```
// vulnerable.compact
export circuit withdraw(): [] {
  assert(ownPublicKey() == vault_owner, "Not the vault owner");
}
```

`vault_owner` is public ledger state. Any attacker can:
1. Read `vault_owner` from the chain
2. Set `ownPublicKey()` to that value in their `CircuitContext`
3. Generate a valid ZK proof — `assert(storedOwner == storedOwner)` passes
4. Submit the transaction — no secret key required

---

## The Fix

```
// secure.compact
circuit ownerCommitment(sk: Bytes<32>): Bytes<32> {
  return persistentHash<Vector<2, Bytes<32>>>([pad(32, "vault:owner:"), sk]);
}

export circuit withdraw(): [] {
  assert(
    ownerCommitment(localSecretKey()) == vault_owner,
    "Not the vault owner"
  );
}
```

The ZK proof now proves: *"I know an `sk` such that `hash("vault:owner:", sk) == vault_owner`."*

An attacker who reads `vault_owner` cannot reverse `persistentHash` to find `sk`. No valid proof is possible without the original secret key.

This is the same pattern used in [midnightntwrk/example-bboard](https://github.com/midnightntwrk/example-bboard).

---

## Affected Code in Production

OpenZeppelin's `Ownable.compact` uses `ownPublicKey()` in `assertOnlyOwner()`:

```
export circuit assertOnlyOwner(): [] {
  Initializable_assertInitialized();
  const caller = ownPublicKey();
  assert(caller == _owner.left, "Ownable: caller is not the owner");
}
```

Every contract importing `Ownable.compact` and calling `assertOnlyOwner()` is vulnerable until this is patched.

---

## Compilation

All Compact contracts verified against **compiler v0.30.0** using the [Midnight MCP toolchain](https://www.npmjs.com/package/midnight-mcp).

```bash
npx midnight-mcp
# Then use the midnight-compile-contract tool on each .compact file
```

---

## Reference

- [example-bboard](https://github.com/midnightntwrk/example-bboard) — correct witness + persistentHash pattern
- [OpenZeppelin compact-contracts](https://github.com/OpenZeppelin/compact-contracts) — affected library
- [Midnight Docs](https://docs.midnight.network)
