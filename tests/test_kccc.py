"""Tests for KCCC (Key-Controlled Chained-CNOT) encryption from Jacqmin & Liénardy (arXiv:2603.19985).

Validates:
1. keyspace_size(n) == factorial(n) * 4**n and iter_keys yields exactly that many DISTINCT keys for n=2,3.
2. E^CNOT with k1 the identity permutation applies NO CNOTs at all (every CNOT_{i,i} is identity),
   so the layer-1 tableau equals the identity tableau.
3. H_k2 with k2 all zeros is the identity; with k2 all ones it is H on every qubit (compared via tableaus).
4. The transp layer with all tau_i = 0 is identity; with tau_1 = 1 it swaps qubits 1 and n (0 and n-1),
   verified on an explicit basis state.
5. Exact condition probabilities: Pr(k1(1)=1) == 1/n, Pr(k2_1=0) == 0.5, Pr(tau_1=0) == 0.5 for n=2,3,4.
6. Forgery survival rate >= 1/(4n) for n=2,3,4 (sharp prediction from Jacqmin-Liénardy lower bound).
7. rate*n constancy across n=2,3,4 (ratio max/min < 2.0), confirming 1/n scaling.
"""

from __future__ import annotations

import math
import pytest
import stim

from pauliguard.analysis.scaling import (
    kccc_condition_breakdown,
    kccc_forgery_survival,
)
from pauliguard.engine.encryption import KCCC
from pauliguard.engine.pauli import Pauli


def test_kccc_keyspace_size_and_distinct_keys() -> None:
    """1. keyspace_size(n) == factorial(n) * 4**n and iter_keys yields exactly that many DISTINCT keys for n=2,3."""
    enc = KCCC()
    for n in (2, 3):
        expected_size = math.factorial(n) * (4**n)
        assert enc.keyspace_size(n) == expected_size, (
            f"Keyspace size mismatch for n={n}: expected {expected_size}, got {enc.keyspace_size(n)}"
        )

        keys = list(enc.iter_keys(n))
        assert len(keys) == expected_size, (
            f"iter_keys length mismatch for n={n}: expected {expected_size}, got {len(keys)}"
        )

        distinct_keys = set(keys)
        assert len(distinct_keys) == expected_size, (
            f"iter_keys produced duplicate keys for n={n}: {len(distinct_keys)} unique vs {len(keys)} total"
        )


def test_kccc_cnot_identity_layer() -> None:
    """2. E^CNOT with k1 the identity permutation applies NO CNOTs at all (every CNOT_{i,i} is identity),

    so the layer-1 tableau equals the identity tableau. Assert this exactly.
    """
    enc = KCCC(perm_variant="transp")
    for n in (1, 2, 3, 4):
        ident_k1 = tuple(range(n))
        zero_k2 = (0,) * n
        zero_k3 = (0,) * n
        key = (ident_k1, zero_k2, zero_k3)

        tab = enc.tableau(key, n)
        ident_tab = stim.Tableau(n)
        assert tab == ident_tab, (
            f"Layer 1 tableau with identity permutation k1 must equal identity tableau for n={n}"
        )


def test_kccc_hadamard_layer() -> None:
    """3. H_k2 with k2 all zeros is the identity; with k2 all ones it is H on every qubit.

    Verify by comparing tableaus.
    """
    enc = KCCC(perm_variant="transp")
    for n in (1, 2, 3, 4):
        ident_k1 = tuple(range(n))
        zero_k3 = (0,) * n

        # k2 all zeros -> identity tableau
        key_zeros = (ident_k1, (0,) * n, zero_k3)
        tab_zeros = enc.tableau(key_zeros, n)
        assert tab_zeros == stim.Tableau(n), f"H_k2 with k2=0 must be identity for n={n}"

        # k2 all ones -> H on every qubit
        key_ones = (ident_k1, (1,) * n, zero_k3)
        tab_ones = enc.tableau(key_ones, n)

        circuit_h = stim.Circuit()
        for i in range(n):
            circuit_h.append("H", [i])
        expected_h_tab = stim.Tableau.from_circuit(circuit_h)

        assert tab_ones == expected_h_tab, (
            f"H_k2 with k2=1 must equal H on every qubit for n={n}"
        )


def test_kccc_transposition_layer_basis_state() -> None:
    """4. The transp layer with all tau_i = 0 is the identity; with tau_1 = 1 it swaps qubits 1 and n (0 and n-1).

    Verify on an explicit basis state.
    """
    enc = KCCC(perm_variant="transp")
    for n in (2, 3, 4):
        ident_k1 = tuple(range(n))
        zero_k2 = (0,) * n

        # (a) All tau_i = 0 -> identity
        key_ident = (ident_k1, zero_k2, (0,) * n)
        tab_ident = enc.tableau(key_ident, n)
        assert tab_ident == stim.Tableau(n)

        # (b) tau_1 = 1 (k3[0]=1, k3[n-1]=0 -> tau_0 = 1), other tau_i = 0
        # This corresponds to swapping qubit 0 and qubit n-1 (qubits 1 and n in 1-based indexing)
        k3_swap = [0] * n
        k3_swap[0] = 1
        key_swap = (ident_k1, zero_k2, tuple(k3_swap))
        tab_swap = enc.tableau(key_swap, n)

        # Verify on explicit basis state |1 0 ... 0> (qubit 0 is 1, rest 0)
        # After swapping qubits 0 and n-1, state must be |0 ... 0 1> (qubit n-1 is 1, rest 0)
        sim = stim.TableauSimulator()
        sim.do(stim.Circuit("X 0"))  # Prepare |1 0 ... 0>
        sim.do(tab_swap.to_circuit())

        # Check Z expectation values: |0> has peek_z = +1, |1> has peek_z = -1
        assert sim.peek_z(0) == 1, f"Qubit 0 should be |0> after swap for n={n}"
        assert sim.peek_z(n - 1) == -1, f"Qubit {n-1} should be |1> after swap for n={n}"
        for i in range(1, n - 1):
            assert sim.peek_z(i) == 1, f"Intermediate qubit {i} should remain |0> for n={n}"


def test_kccc_condition_probabilities_exact() -> None:
    """5. CONDITION PROBABILITIES: kccc_condition_breakdown(n) must give p_k1_fixes_first == 1/n

    EXACTLY, p_k2_first_zero == 0.5 exactly, p_tau1_zero == 0.5 exactly, for n=2,3,4.
    Assert exact equality (these are exhaustive enumerations of a finite keyspace, so they are
    exact rationals, not estimates).
    """
    for n in (2, 3, 4):
        breakdown = kccc_condition_breakdown(n, variant="transp")

        # Assert exact rational equality
        assert breakdown["p_k1_fixes_first"] == 1.0 / n, (
            f"p_k1_fixes_first for n={n}: expected exact {1.0/n}, got {breakdown['p_k1_fixes_first']}"
        )
        assert breakdown["p_k2_first_zero"] == 0.5, (
            f"p_k2_first_zero for n={n}: expected exact 0.5, got {breakdown['p_k2_first_zero']}"
        )
        assert breakdown["p_tau1_zero"] == 0.5, (
            f"p_tau1_zero for n={n}: expected exact 0.5, got {breakdown['p_tau1_zero']}"
        )
        assert breakdown["p_joint"] == 1.0 / (4.0 * n), (
            f"p_joint for n={n}: expected exact {1.0/(4.0*n)}, got {breakdown['p_joint']}"
        )


def test_kccc_forgery_survival_lower_bound_validation() -> None:
    """6. THE VALIDATION: kccc_forgery_survival(n) rate must be >= 1/(4n) for n=2,3,4.

    Assert the inequality (the paper states a LOWER bound, so >= is the correct assertion, not ==).
    Put the measured rate, the reference 1/(4n) and the ratio in the assertion message.
    """
    for n in (2, 3, 4):
        res = kccc_forgery_survival(n, variant="transp", U_letter="X")
        rate = res["rate"]
        ref = res["reference"]
        ratio = res["ratio"]

        assert rate >= ref, (
            f"KCCC forgery survival validation failed for n={n}: "
            f"measured rate={rate:.6f} < reference 1/(4n)={ref:.6f} (ratio={ratio:.4f}). "
            f"Paper predicts rate >= 1/(4n)."
        )


def test_kccc_rate_times_n_constancy() -> None:
    """7. rate*n should be roughly constant across n=2,3,4 (ratio max/min < 2.0), confirming the 1/n

    scaling. Report the values in the assertion message.
    """
    rates_n = {}
    for n in (2, 3, 4):
        res = kccc_forgery_survival(n, variant="transp", U_letter="X")
        rates_n[n] = res["rate_times_n"]

    values = list(rates_n.values())
    max_val = max(values)
    min_val = min(values)
    ratio = max_val / min_val if min_val > 0 else float("inf")

    rates_n_str = ", ".join(f"n={n}: rate*n={rn:.4f}" for n, rn in rates_n.items())
    assert ratio < 2.0, (
        f"rate*n is not approximately constant across n=2,3,4: "
        f"max/min ratio={ratio:.4f} >= 2.0. Observed values: [{rates_n_str}]."
    )
