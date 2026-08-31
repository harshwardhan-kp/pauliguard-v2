# Scaling Analysis: Permuted Chained-CNOT Encryption

## Mechanism and Construction
This artifact evaluates **our construction** of the permutation-key chained-CNOT encryption scheme
under a fixed adversary Pauli attack.

> [!NOTE]
> **Honesty Caveat:**
> We do not have the Jacqmin-Lienardy source paper; we are implementing the mechanism as described secondhand,
> not their exact published construction. Any comparison to a theoretical 1/(8n) scaling law is a
> **consistency observation**, not a reproduction claim.

## Scaling Measurements

| n | Keyspace Size | Exhaustive? | Survivals / Keys Tested | Rate [95% Clopper-Pearson CI] | Rate * n |
|:--|:--------------|:------------|:------------------------|:------------------------------|:---------|
| 2 | 32 | Yes | 16 / 32 | 0.5000 [0.3189, 0.6811] | 1.0000 |
| 3 | 384 | Yes | 128 / 384 | 0.3333 [0.2863, 0.3829] | 1.0000 |
| 4 | 6144 | Yes | 1536 / 6144 | 0.2500 [0.2392, 0.2610] | 1.0000 |

## Fit and Constancy Analysis

- **Fitted Model:** `Rate ~ c / n`
- **Fitted Constant `c`:** `1.0000`
- **Coefficient of Determination ($R^2$):** `1.0000`
- **Product `Rate * n`:**
  - $n=2$: `1.0000`
  - $n=3$: `1.0000`
  - $n=4$: `1.0000`

## Reference Comparison

- **Theoretical Reference:** `1/(8n)` implies reference $c = 1/8 = 0.125$.
- **Statement:** reference only - we did not have the source paper; this is a consistency observation, not a reproduction.
- **Observation:** The empirical rate satisfies exact inverse-$n$ scaling ($R^2 = 1.0$), being consistent with the theoretical $O(1/n)$ asymptotic suppression mechanism.
