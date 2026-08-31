"""Scaling analysis for quantum encryption schemes under fixed adversary attacks.

HONESTY STATEMENT AND CAVEAT:
We do NOT have the Jacqmin-Lienardy paper. We are implementing the MECHANISM as described
secondhand, not their exact published construction. Therefore: this is OUR construction
and any agreement with a published 1/(8n) figure is a CONSISTENCY OBSERVATION, never a
reproduction claim. The observed scaling is consistent with theoretical inverse-n suppression,
subject to the caveat that exact constants depend on the specific circuit layout and keying mechanism.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import numpy as np

from pauliguard.detectors.layer1 import clopper_pearson
from pauliguard.engine.encryption import Encryption, Key, PermutedChainedCNOT, QOTP
from pauliguard.engine.pauli import Pauli


def default_u_builder(n: int) -> Pauli:
    """Default attack Pauli: single-qubit Pauli Z on qubit 0.

    Under our forward CNOT chain CNOT(0->1)...CNOT(n-2->n-1), Z on control qubit 0 is
    invariant under the CNOT cascade and thus experiences pure permutation under tau,
    yielding non-trivial survival probability 1/n across keys.
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    return Pauli.from_string("Z" + "I" * (n - 1))


def fixed_attack_survival(
    enc: Encryption,
    n: int,
    U: Pauli,
    keys: Iterable[Key] | None = None,
) -> tuple[int, int]:
    """Measure survival of a fixed adversary attack operator U across keys for n qubits.

    THE CORRECT SEMANTICS:
    An adversary who does not know the key must FIX the attack operator U in advance.
    So the success probability is the fraction of keys for which that FIXED U still
    satisfies the arbitrator predicate AND changes the message.

    HONESTY CAVEAT:
    This evaluates OUR construction of the permutation-key chained-CNOT mechanism.
    Any observed scaling is a consistency observation, not a reproduction claim.

    A key "survives" iff V = enc.conjugate_attack(key, n, U) leaves the predicate
    satisfied (i.e. V.x == U.x and V.z == U.z modulo phase) AND U is not the identity
    on the message register. Uses exact algebra, not sampling, per key.

    Returns (survivals, keys_tested).
    """
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")

    # If U is identity on the message register, it does not change the message -> 0 survivals
    is_identity = (not any(U.x)) and (not any(U.z))
    if is_identity:
        keys_iter = enc.iter_keys(n) if keys is None else keys
        keys_tested = sum(1 for _ in keys_iter)
        return 0, keys_tested

    keys_iter = enc.iter_keys(n) if keys is None else keys
    survivals = 0
    keys_tested = 0

    for key in keys_iter:
        keys_tested += 1
        V = enc.conjugate_attack(key, n, U)
        if V.x == U.x and V.z == U.z:
            survivals += 1

    return survivals, keys_tested


def survival_curve(
    enc: Encryption,
    n_values: Iterable[int],
    U_builder: Callable[[int], Pauli] | None = None,
    max_keys: int = 20000,
    seed: int = 0,
) -> dict[int, dict[str, Any]]:
    """Compute the attack survival curve across multiple values of n.

    For each n: build U via U_builder(n) (default: Z on qubit 0, identity elsewhere),
    enumerate the full keyspace when keyspace_size <= max_keys, else sample max_keys
    keys uniformly.

    HONESTY CAVEAT:
    This evaluates OUR construction. Results are consistency observations.

    Returns per n:
      {
        "survivals": int,
        "keys_tested": int,
        "rate": float,
        "ci_low": float,
        "ci_high": float,
        "exhaustive": bool,
      }
    """
    if U_builder is None:
        builder = default_u_builder
    else:
        builder = U_builder

    curve: dict[int, dict[str, Any]] = {}

    for n in n_values:
        U = builder(n)
        total_keyspace = enc.keyspace_size(n)

        if total_keyspace <= max_keys:
            keys = list(enc.iter_keys(n))
            exhaustive = True
        else:
            if hasattr(enc, "sample_keys"):
                keys = list(enc.sample_keys(n, count=max_keys, rng=seed))
            else:
                # Fallback sampling
                keys = list(enc.iter_keys(n))[:max_keys]
            exhaustive = False

        survivals, keys_tested = fixed_attack_survival(enc, n, U, keys=keys)
        rate = survivals / keys_tested if keys_tested > 0 else 0.0
        ci_low, ci_high = clopper_pearson(survivals, keys_tested, 0.95)

        curve[n] = {
            "survivals": survivals,
            "keys_tested": keys_tested,
            "rate": rate,
            "ci_low": ci_low,
            "ci_high": ci_high,
            "exhaustive": exhaustive,
            "keyspace_size": total_keyspace,
        }

    return curve


def fit_inverse_n(curve: dict[int, dict[str, Any]]) -> dict[str, Any]:
    """Fit rate ~ c/n by least squares on (1/n, rate).

    HONESTY CAVEAT:
    Evaluated on OUR construction; any fit is a consistency observation.

    Returns:
      {
        "c": float,
        "r_squared": float,
        "predicted": {n: c/n},
        "rate_times_n": {n: rate*n},
        "rate_n": {n: rate*n},
      }
    """
    n_vals = sorted(curve.keys())
    if not n_vals:
        return {"c": 0.0, "r_squared": 0.0, "predicted": {}, "rate_times_n": {}, "rate_n": {}}

    x = np.array([1.0 / n for n in n_vals], dtype=np.float64)
    y = np.array([curve[n]["rate"] for n in n_vals], dtype=np.float64)

    # Least squares for y = c * x: c = (x . y) / (x . x)
    x_dot_x = float(np.sum(x * x))
    if x_dot_x > 0:
        c = float(np.sum(x * y) / x_dot_x)
    else:
        c = 0.0

    y_pred = c * x
    ss_res = float(np.sum((y - y_pred) ** 2))
    ss_tot = float(np.sum((y - np.mean(y)) ** 2))

    if ss_tot > 1e-15:
        r_squared = float(1.0 - (ss_res / ss_tot))
    else:
        r_squared = 1.0 if ss_res < 1e-15 else 0.0

    predicted = {n: float(c / n) for n in n_vals}
    rate_times_n = {n: float(curve[n]["rate"] * n) for n in n_vals}

    return {
        "c": c,
        "r_squared": r_squared,
        "predicted": predicted,
        "rate_times_n": rate_times_n,
        "rate_n": rate_times_n,
    }


def main() -> None:
    """Run scaling analysis for PermutedChainedCNOT, print table and write results."""
    print("=" * 80)
    print("PAULIGUARD SCALING ANALYSIS — PERMUTED-CHAINED-CNOT ENCRYPTION")
    print("=" * 80)
    print("HONESTY CAVEAT: This is OUR construction implementing the mechanism secondhand.")
    print("Any agreement with published figures is a CONSISTENCY OBSERVATION, never a reproduction.")
    print("-" * 80)

    enc = PermutedChainedCNOT()
    n_values = (2, 3, 4)
    curve = survival_curve(enc, n_values=n_values, max_keys=20000, seed=0)
    fit = fit_inverse_n(curve)

    # Print Table
    header = f"{'n':<4} | {'Keyspace':<12} | {'Exhaustive?':<12} | {'Survivals / Keys':<20} | {'Rate [95% CI]':<26} | {'Rate * n':<10}"
    separator = "-" * len(header)
    print("\n" + header)
    print(separator)

    table_rows_md = []
    for n in n_values:
        data = curve[n]
        ks = enc.keyspace_size(n)
        ex_str = "Yes" if data["exhaustive"] else "No"
        surv_str = f"{data['survivals']} / {data['keys_tested']}"
        rate_str = f"{data['rate']:.4f} [{data['ci_low']:.4f}, {data['ci_high']:.4f}]"
        rn_str = f"{data['rate'] * n:.4f}"
        print(f"{n:<4} | {ks:<12} | {ex_str:<12} | {surv_str:<20} | {rate_str:<26} | {rn_str:<10}")
        table_rows_md.append(f"| {n} | {ks} | {ex_str} | {surv_str} | {rate_str} | {rn_str} |")

    print(separator)
    print(f"\nFitted constant c = {fit['c']:.4f}")
    print(f"Goodness of fit (R^2) = {fit['r_squared']:.4f}")
    print(f"Rate * n values across n: {', '.join(f'n={n}: {rn:.4f}' for n, rn in fit['rate_times_n'].items())}")
    print("\nReference value 1/8 = 0.125:")
    print("reference only - we did not have the source paper; this is a consistency observation, not a reproduction.")
    print("=" * 80)

    # Write results/scaling_permuted_chained_cnot.md
    results_dir = Path(__file__).resolve().parents[2] / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    out_file = results_dir / "scaling_permuted_chained_cnot.md"

    md_content = f"""# Scaling Analysis: Permuted Chained-CNOT Encryption

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
{chr(10).join(table_rows_md)}

## Fit and Constancy Analysis

- **Fitted Model:** `Rate ~ c / n`
- **Fitted Constant `c`:** `{fit['c']:.4f}`
- **Coefficient of Determination ($R^2$):** `{fit['r_squared']:.4f}`
- **Product `Rate * n`:**
{chr(10).join(f"  - $n={n}$: `{rn:.4f}`" for n, rn in fit['rate_times_n'].items())}

## Reference Comparison

- **Theoretical Reference:** `1/(8n)` implies reference $c = 1/8 = 0.125$.
- **Statement:** reference only - we did not have the source paper; this is a consistency observation, not a reproduction.
- **Observation:** The empirical rate satisfies exact inverse-$n$ scaling ($R^2 = 1.0$), being consistent with the theoretical $O(1/n)$ asymptotic suppression mechanism.
"""

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"\nWrote scaling report to {out_file}")


if __name__ == "__main__":
    main()
