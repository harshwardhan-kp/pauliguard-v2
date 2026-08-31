"""Tests for Layer 3 — ALGEBRAIC MALLEABILITY detector.

Verifies GF(2) primitives, symplectic representation, and the headline claim:
L3 finds a non-trivial malleability subspace on lu-2022 with QOTP, emits
confirmed certificates with success_probability EXACTLY 1.0, and returns
ZERO certificates on decoy-bb84-qds (the contrast case).
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
import stim

from pauliguard.detectors.layer3 import (
    Layer3,
    MalleabilityCertificate,
    clifford_to_symplectic,
    gf2_nullspace,
    gf2_rank,
    gf2_rref,
    gf2_solve,
    pauli_to_vector,
    symplectic_form,
    vector_to_pauli,
)
from pauliguard.engine.encryption import QOTP, ChainedCNOT
from pauliguard.engine.pauli import Pauli, conjugate
from pauliguard.engine.spec_loader import load_spec

SPECS_DIR = Path(__file__).resolve().parent.parent / "pauliguard" / "specs"


# =========================================================================
#  1. GF(2) primitives
# =========================================================================

class TestGF2Primitives:
    """GF(2) linear-algebra primitives: rref, rank, nullspace, solve."""

    def test_gf2_rank_random_matrices(self) -> None:
        """gf2_rank agrees with an independent computation on 200 random matrices.

        Independent computation: rank of the transpose (which must equal the
        rank of the original, by the rank theorem).
        """
        rng = np.random.default_rng(seed=20260831)
        for _ in range(200):
            m = rng.integers(1, 12)
            n = rng.integers(1, 12)
            M = rng.integers(0, 2, size=(m, n)).astype(np.uint8)

            r = gf2_rank(M)
            r_t = gf2_rank(M.T)
            assert r == r_t, (
                f"Rank of M ({r}) != rank of M^T ({r_t}) for shape ({m}, {n})"
            )
            # Also verify rank <= min(m, n)
            assert r <= min(m, n)

    def test_gf2_nullspace_satisfies_equations(self) -> None:
        """gf2_nullspace rows genuinely satisfy M v = 0 mod 2, and
        rank + nullity == ncols.
        """
        rng = np.random.default_rng(seed=42)
        for _ in range(200):
            m = rng.integers(1, 12)
            n = rng.integers(1, 12)
            M = rng.integers(0, 2, size=(m, n)).astype(np.uint8)

            ns = gf2_nullspace(M)
            r = gf2_rank(M)

            # rank + nullity == ncols
            nullity = ns.shape[0]
            assert r + nullity == n, (
                f"rank ({r}) + nullity ({nullity}) != ncols ({n})"
            )

            # Each nullspace vector satisfies M v = 0 mod 2
            for row in ns:
                product = (M @ row) & 1
                assert np.all(product == 0), (
                    f"Nullspace vector {row} does not satisfy Mv=0 mod 2"
                )

    def test_gf2_solve_consistent(self) -> None:
        """gf2_solve returns a genuine solution when one exists."""
        rng = np.random.default_rng(seed=123)
        for _ in range(100):
            m = rng.integers(1, 10)
            n = rng.integers(1, 10)
            A = rng.integers(0, 2, size=(m, n)).astype(np.uint8)
            # Generate a consistent system: pick x, compute b = Ax mod 2
            x_true = rng.integers(0, 2, size=n).astype(np.uint8)
            b = (A @ x_true) & 1

            x_sol = gf2_solve(A, b)
            assert x_sol is not None, "gf2_solve returned None for a consistent system"
            # Verify solution
            assert np.all(((A @ x_sol) & 1) == b), (
                f"gf2_solve solution does not satisfy Ax = b mod 2"
            )

    def test_gf2_solve_inconsistent(self) -> None:
        """gf2_solve returns None when the system is inconsistent."""
        # System: x = 0, x = 1 (inconsistent)
        A = np.array([[1], [1]], dtype=np.uint8)
        b = np.array([0, 1], dtype=np.uint8)
        assert gf2_solve(A, b) is None


# =========================================================================
#  2. clifford_to_symplectic is SYMPLECTIC
# =========================================================================

class TestSymplectic:
    """clifford_to_symplectic preserves the symplectic form."""

    def test_symplectic_form_preserved(self) -> None:
        """M^T J M == J over GF(2) for various Clifford tableaux."""
        rng = np.random.default_rng(seed=99)
        for n in (1, 2, 3, 4):
            J = symplectic_form(n)
            for _ in range(10):
                # Random Clifford via random circuit
                circuit = stim.Circuit()
                circuit.append("I", list(range(n)))
                gates = ["H", "S", "CNOT"]
                depth = rng.integers(3, 10)
                for _ in range(depth):
                    gate = gates[int(rng.integers(0, len(gates)))]
                    if gate == "CNOT" and n > 1:
                        q1, q2 = rng.choice(n, size=2, replace=False)
                        circuit.append("CNOT", [int(q1), int(q2)])
                    else:
                        q = int(rng.integers(0, n))
                        circuit.append(gate if gate != "CNOT" else "H", [q])

                tab = stim.Tableau.from_circuit(circuit)
                M = clifford_to_symplectic(tab, n)

                # Check M^T J M == J mod 2
                product = (M.T @ J @ M) & 1
                assert np.array_equal(product, J), (
                    f"Symplectic form not preserved for n={n}:\n"
                    f"M^T J M =\n{product}\nJ =\n{J}"
                )


# =========================================================================
#  3. clifford_to_symplectic agrees with direct conjugation
# =========================================================================

class TestSymplecticConjugation:
    """clifford_to_symplectic agrees with direct conjugation for random Cliffords and Paulis."""

    def test_agrees_with_conjugation(self) -> None:
        """For 50 random Cliffords and random Paulis, M_C * vec(P) == vec(conjugate(C, P)) mod 2."""
        rng = np.random.default_rng(seed=2026)
        count = 0
        for n in (1, 2, 3):
            for _ in range(50):
                # Random Clifford
                circuit = stim.Circuit()
                circuit.append("I", list(range(n)))
                gates = ["H", "S", "CNOT"]
                depth = rng.integers(3, 8)
                for _ in range(depth):
                    gate = gates[int(rng.integers(0, len(gates)))]
                    if gate == "CNOT" and n > 1:
                        q1, q2 = rng.choice(n, size=2, replace=False)
                        circuit.append("CNOT", [int(q1), int(q2)])
                    else:
                        q = int(rng.integers(0, n))
                        circuit.append(gate if gate != "CNOT" else "H", [q])

                tab = stim.Tableau.from_circuit(circuit)
                M = clifford_to_symplectic(tab, n)

                # Random Pauli
                x_bits = tuple(int(b) for b in rng.integers(0, 2, size=n))
                z_bits = tuple(int(b) for b in rng.integers(0, 2, size=n))
                P = Pauli(n=n, x=x_bits, z=z_bits, phase=0)
                v_P = pauli_to_vector(P, n)

                # Matrix multiplication
                v_result = (M @ v_P) & 1

                # Direct conjugation
                conj_P = conjugate(tab, P)
                v_conj = pauli_to_vector(conj_P, n)

                assert np.array_equal(v_result, v_conj), (
                    f"Symplectic matrix disagrees with conjugation:\n"
                    f"M*v(P) = {v_result}, v(conj(C,P)) = {v_conj}"
                )
                count += 1

        # Verify we tested at least 50 across all n values
        assert count >= 50


# =========================================================================
#  4. KNOWN-ANSWER TEST: lu-2022 with QOTP
# =========================================================================

class TestLu2022KnownAnswer:
    """Headline validation: L3 finds malleability in lu-2022."""

    @pytest.fixture
    def lu2022_certs(self) -> list[MalleabilityCertificate]:
        spec = load_spec(SPECS_DIR / "lu-2022.yaml")
        enc = QOTP()
        l3 = Layer3(spec, enc)
        n = spec.n_message_qubits
        certs = l3.analyse(n, trials=200)
        return certs

    def test_finds_nontrivial_malleability(self, lu2022_certs: list[MalleabilityCertificate]) -> None:
        """L3 finds at least one certificate on lu-2022."""
        assert len(lu2022_certs) >= 1, (
            "L3 should find at least one malleability certificate for lu-2022"
        )

    def test_malleability_dimension_positive(self, lu2022_certs: list[MalleabilityCertificate]) -> None:
        """The malleability dimension is positive."""
        for cert in lu2022_certs:
            assert cert.malleability_dimension > 0

    def test_success_probability_exactly_one(self, lu2022_certs: list[MalleabilityCertificate]) -> None:
        """Success probability is EXACTLY 1.0 (assert ==, not approx)."""
        for cert in lu2022_certs:
            assert cert.success_probability == 1.0, (
                f"Expected success_probability == 1.0, got {cert.success_probability}"
            )

    def test_confirmed_by_execution(self, lu2022_certs: list[MalleabilityCertificate]) -> None:
        """confirmed_by_execution is True and execution_accepted == execution_trials
        and message_changed == execution_trials.
        """
        for cert in lu2022_certs:
            assert cert.confirmed_by_execution is True
            assert cert.execution_accepted == cert.execution_trials, (
                f"execution_accepted ({cert.execution_accepted}) != "
                f"execution_trials ({cert.execution_trials})"
            )
            assert cert.message_changed == cert.execution_trials, (
                f"message_changed ({cert.message_changed}) != "
                f"execution_trials ({cert.execution_trials})"
            )


# =========================================================================
#  5. Every certificate has confirmed_by_execution True
# =========================================================================

class TestPrecisionByConstruction:
    """Every returned certificate has confirmed_by_execution True (precision 1)."""

    def test_all_confirmed(self) -> None:
        spec = load_spec(SPECS_DIR / "lu-2022.yaml")
        enc = QOTP()
        l3 = Layer3(spec, enc)
        certs = l3.analyse(spec.n_message_qubits, trials=100)
        for cert in certs:
            assert cert.confirmed_by_execution is True, (
                f"Certificate for {cert.witness_pauli} is not confirmed by execution"
            )


# =========================================================================
#  6. Caveat field is non-empty and contains "sound" and "not complete"
# =========================================================================

class TestCaveat:
    """The certificate caveat field is non-empty and contains required text."""

    def test_caveat_content(self) -> None:
        spec = load_spec(SPECS_DIR / "lu-2022.yaml")
        enc = QOTP()
        l3 = Layer3(spec, enc)
        certs = l3.analyse(spec.n_message_qubits, trials=100)
        assert len(certs) > 0
        for cert in certs:
            assert cert.caveat, "Caveat field is empty"
            lower = cert.caveat.lower()
            assert "sound" in lower, f"Caveat missing 'sound': {cert.caveat}"
            assert "not complete" in lower, f"Caveat missing 'not complete': {cert.caveat}"


# =========================================================================
#  7. At least one certificate has -1 in commutation_sign_range
# =========================================================================

class TestAnticommutingInstance:
    """At least one certificate has -1 in commutation_sign_range."""

    def test_anticommuting_sign_present(self) -> None:
        spec = load_spec(SPECS_DIR / "lu-2022.yaml")
        enc = QOTP()
        l3 = Layer3(spec, enc)
        certs = l3.analyse(spec.n_message_qubits, trials=100)
        assert len(certs) > 0

        has_minus_one = any(-1 in cert.commutation_sign_range for cert in certs)
        assert has_minus_one, (
            "Expected at least one certificate with -1 in commutation_sign_range "
            "(the anticommuting instance), but none found. "
            f"Sign ranges: {[c.commutation_sign_range for c in certs]}"
        )


# =========================================================================
#  8. CONTRAST: decoy-bb84-qds returns ZERO certificates
# =========================================================================

class TestContrastDecoyBB84:
    """L3 returns ZERO certificates on decoy-bb84-qds.

    This is the triage result — statistics do the work on that lineage,
    algebra does the work on the teleportation lineage.
    """

    def test_no_certificates(self) -> None:
        spec = load_spec(SPECS_DIR / "decoy-bb84-qds.yaml")
        # decoy-bb84-qds has encryption="none"
        l3 = Layer3(spec, None)
        certs = l3.analyse(spec.n_message_qubits, trials=100)
        assert len(certs) == 0, (
            f"Expected ZERO certificates for decoy-bb84-qds, got {len(certs)}. "
            "This is the triage result: statistics do the work on the decoy-state "
            "lineage, algebra does the work on the teleportation lineage."
        )
