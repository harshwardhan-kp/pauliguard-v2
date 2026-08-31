"""Tests for scaling analysis and PermutedChainedCNOT encryption.

HONESTY CAVEAT:
We do NOT have the Jacqmin-Lienardy paper. We are testing OUR construction of the
mechanism as described secondhand, not the exact published construction. Any scaling
relationship or agreement is a CONSISTENCY OBSERVATION, never a reproduction claim.
"""

from __future__ import annotations

import math
import pytest
import stim

from pauliguard.analysis.scaling import (
    fit_inverse_n,
    fixed_attack_survival,
    survival_curve,
)
from pauliguard.engine.encryption import PermutedChainedCNOT, QOTP
from pauliguard.engine.pauli import Pauli


def test_keyspace_size_and_distinct_keys() -> None:
    """1. keyspace_size(n) == 4**n * factorial(n) and iter_keys yields exactly that many DISTINCT keys for n=1,2,3."""
    enc = PermutedChainedCNOT()
    for n in (1, 2, 3):
        expected_size = (4**n) * math.factorial(n)
        assert enc.keyspace_size(n) == expected_size, (
            f"Keyspace size mismatch for n={n}: expected {expected_size}, got {enc.keyspace_size(n)}"
        )

        keys = list(enc.iter_keys(n))
        assert len(keys) == expected_size, (
            f"iter_keys count mismatch for n={n}: expected {expected_size}, got {len(keys)}"
        )

        # Assert all yielded keys are distinct
        distinct_keys = set(keys)
        assert len(distinct_keys) == expected_size, (
            f"iter_keys produced duplicate keys for n={n}: {len(distinct_keys)} distinct out of {len(keys)}"
        )


def test_permutation_layer_genuinely_permutes() -> None:
    """2. Every tableau built is a valid stim.Tableau and the permutation layer genuinely permutes:

    for a non-identity tau, conjugating a single-qubit Pauli X on qubit 0 yields a Pauli whose
    support is on qubit tau(0) or moved by the CNOT chain. Assert the support CHANGES for at
    least one tau, so the permutation is not a no-op.
    """
    enc = PermutedChainedCNOT()
    n = 3

    # Check validity of tableau across sample keys
    zero_key_ident = ((0, 0, 0), (0, 0, 0), (0, 1, 2))
    tab_ident = enc.tableau(zero_key_ident, n)
    assert isinstance(tab_ident, stim.Tableau)

    # Test with non-identity permutations
    u_x0 = Pauli.from_string("XII")
    u_z0 = Pauli.from_string("ZII")
    u_x2 = Pauli.from_string("IIX")

    # Conjugate under identity tau = (0, 1, 2)
    v_z0_ident = enc.conjugate_attack(((0, 0, 0), (0, 0, 0), (0, 1, 2)), n, u_z0)
    v_x2_ident = enc.conjugate_attack(((0, 0, 0), (0, 0, 0), (0, 1, 2)), n, u_x2)

    # Conjugate under non-identity tau = (1, 0, 2)
    v_z0_swap = enc.conjugate_attack(((0, 0, 0), (0, 0, 0), (1, 0, 2)), n, u_z0)
    # Conjugate under non-identity tau = (2, 1, 0)
    v_x2_swap = enc.conjugate_attack(((0, 0, 0), (0, 0, 0), (2, 1, 0)), n, u_x2)

    # Verify that support genuinely changes
    assert v_z0_ident.to_string() == "+ZII"
    assert v_z0_swap.to_string() == "+IZI"  # Support moved from qubit 0 to qubit tau(0) = 1
    assert v_x2_ident.to_string() == "+IIX"
    assert v_x2_swap.to_string() == "+XII"  # Support moved from qubit 2 to qubit tau(2) = 0

    # Also verify that conjugating X on qubit 0 spreads across qubits via CNOT chain
    v_x0 = enc.conjugate_attack(((0, 0, 0), (0, 0, 0), (0, 1, 2)), n, u_x0)
    assert v_x0.to_string() == "+XXX"
    assert v_x0.x != u_x0.x, "CNOT chain must spread X support across all qubits"


def test_qotp_fixed_attack_survival_is_one() -> None:
    """3. fixed_attack_survival on plain QOTP returns survival rate EXACTLY 1.0

    (sanity anchor: QOTP is fully malleable, every key survives).
    """
    qotp = QOTP()
    for n in (1, 2, 3):
        # Test with various non-identity Paulis
        u_x = Pauli.from_string("X" + "I" * (n - 1))
        u_z = Pauli.from_string("Z" + "I" * (n - 1))

        surv_x, total_x = fixed_attack_survival(qotp, n, u_x)
        assert total_x == qotp.keyspace_size(n)
        assert surv_x == total_x, f"QOTP survival on U=X must be exactly 1.0, got {surv_x}/{total_x}"

        surv_z, total_z = fixed_attack_survival(qotp, n, u_z)
        assert total_z == qotp.keyspace_size(n)
        assert surv_z == total_z, f"QOTP survival on U=Z must be exactly 1.0, got {surv_z}/{total_z}"


def test_permuted_chained_cnot_survival_rate_strictly_between_zero_and_one() -> None:
    """4. fixed_attack_survival on PermutedChainedCNOT returns a rate STRICTLY BETWEEN 0 and 1 for n>=2.

    Assert 0 < rate < 1 - this is the whole point: permutation+chaining makes the attack
    probabilistic rather than certain.
    """
    enc = PermutedChainedCNOT()
    for n in (2, 3, 4):
        u = Pauli.from_string("Z" + "I" * (n - 1))
        surv, total = fixed_attack_survival(enc, n, u)
        rate = surv / total
        assert 0.0 < rate < 1.0, (
            f"PermutedChainedCNOT survival rate for n={n} must be strictly between 0 and 1, got rate={rate:.4f} ({surv}/{total})"
        )


def test_survival_curve_exhaustive_and_strictly_decreasing() -> None:
    """5. survival_curve over n in (2,3,4) is exhaustive (keyspace <= max_keys) and the rate is DECREASING in n.

    Assert strict decrease.
    """
    enc = PermutedChainedCNOT()
    n_values = (2, 3, 4)
    curve = survival_curve(enc, n_values=n_values, max_keys=20000, seed=0)

    # Check exhaustive enumeration
    for n in n_values:
        assert curve[n]["exhaustive"] is True, f"Expected exhaustive enumeration for n={n}"
        assert curve[n]["keys_tested"] == enc.keyspace_size(n)

    # Check strictly decreasing survival rates
    rates = [curve[n]["rate"] for n in n_values]
    for i in range(len(rates) - 1):
        assert rates[i] > rates[i + 1], (
            f"Survival rate must be strictly decreasing with n: n={n_values[i]} (rate={rates[i]:.4f}) "
            f"vs n={n_values[i+1]} (rate={rates[i+1]:.4f})"
        )


def test_rate_times_n_constancy() -> None:
    """6. rate*n is approximately constant across n=2,3,4:

    assert max(rate*n)/min(rate*n) < 2.0, and put the actual values in the assertion message.
    If this fails the law is not c/n and the test must SAY SO rather than being loosened.
    """
    enc = PermutedChainedCNOT()
    n_values = (2, 3, 4)
    curve = survival_curve(enc, n_values=n_values, max_keys=20000, seed=0)
    fit = fit_inverse_n(curve)

    rn_values = [curve[n]["rate"] * n for n in n_values]
    rn_max = max(rn_values)
    rn_min = min(rn_values)
    ratio = rn_max / rn_min if rn_min > 0 else float("inf")

    rn_details = ", ".join(f"n={n}: rate*n={curve[n]['rate'] * n:.4f}" for n in n_values)
    assert ratio < 2.0, (
        f"Scaling law is not consistent with c/n: max(rate*n)/min(rate*n) = {ratio:.4f} >= 2.0. "
        f"Observed products: [{rn_details}], fitted c={fit['c']:.4f}, R^2={fit['r_squared']:.4f}."
    )
