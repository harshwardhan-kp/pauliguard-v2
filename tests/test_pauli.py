"""Tests for exact n-qubit Pauli group implementation over GF(2).

All required correctness properties, round-tripping, algebraic consistency,
and Stim Clifford conjugation are validated here.
"""

from __future__ import annotations

import itertools
import numpy as np
import pytest
import stim

from pauliguard.engine.pauli import Pauli, conjugate


def test_exhaustive_multiplication_matrix_agreement() -> None:
    """1. Exhaustively verify for n=1 and n=2 that for EVERY ordered pair of Paulis

    (all 4^n letter combinations, phase 0), (a*b).to_matrix() equals
    a.to_matrix() @ b.to_matrix() to 1e-12.
    """
    for n in (1, 2):
        letter_tuples = list(itertools.product("IXYZ", repeat=n))
        all_paulis = [Pauli.from_string("".join(letters)) for letters in letter_tuples]
        assert len(all_paulis) == 4**n

        for a in all_paulis:
            for b in all_paulis:
                prod = a * b
                mat_prod = prod.to_matrix()
                expected_mat = a.to_matrix() @ b.to_matrix()
                max_diff = np.max(np.abs(mat_prod - expected_mat))
                assert max_diff < 1e-12, (
                    f"Matrix mismatch for ({a.to_string()}) * ({b.to_string()}): max diff {max_diff}"
                )


def test_exhaustive_commutation_agreement() -> None:
    """2. Exhaustively verify for n=1,2 that commutes() agrees with whether the

    explicit matrices commute (AB == BA) to 1e-12.
    """
    for n in (1, 2):
        letter_tuples = list(itertools.product("IXYZ", repeat=n))
        all_paulis = [Pauli.from_string("".join(letters)) for letters in letter_tuples]

        for a in all_paulis:
            for b in all_paulis:
                alg_commutes = a.commutes(b)
                ma = a.to_matrix()
                mb = b.to_matrix()
                mat_commutes = bool(np.allclose(ma @ mb, mb @ ma, atol=1e-12))
                assert alg_commutes == mat_commutes, (
                    f"Commutation mismatch for a={a.to_string()}, b={b.to_string()}: "
                    f"alg={alg_commutes}, mat={mat_commutes}"
                )


def test_roundtrip_from_and_to_string() -> None:
    """3. Round-trip from_string/to_string over all n=1,2 strings with all four phase tokens."""
    phase_tokens = ["+", "-", "+i", "-i"]
    for n in (1, 2):
        letter_tuples = list(itertools.product("IXYZ", repeat=n))
        for token in phase_tokens:
            for letters in letter_tuples:
                s = f"{token}{''.join(letters)}"
                p = Pauli.from_string(s)
                s_out = p.to_string()
                assert s_out == s, f"String round-trip failed: original '{s}', got '{s_out}'"

                # Double check parsing the output yields an identical Pauli object
                p_again = Pauli.from_string(s_out)
                assert p_again == p, f"Object round-trip failed for '{s}'"


def test_y_matrix_and_phase_relations() -> None:
    """4. Assert Pauli.from_string('Y').to_matrix() equals [[0,-1j],[1j,0]].

    Also check Y == i * X * Z relations exactly.
    """
    p_y = Pauli.from_string("Y")
    expected_y = np.array([[0, -1j], [1j, 0]], dtype=np.complex128)
    assert np.allclose(p_y.to_matrix(), expected_y, atol=1e-12)

    # Check X * Z matrix vs X.to_matrix() @ Z.to_matrix()
    p_x = Pauli.from_string("X")
    p_z = Pauli.from_string("Z")
    p_xz = p_x * p_z
    assert np.allclose(p_xz.to_matrix(), p_x.to_matrix() @ p_z.to_matrix(), atol=1e-12)

    # Check that Y == +i * (X * Z)
    # p_x * p_z has x=(1,), z=(1,), phase=0
    # multiplying with phase +i (phase=1) yields Y (phase=1)
    phase_i = Pauli.from_string("+iI")
    assert phase_i * p_xz == p_y


def test_multiplicative_identity() -> None:
    """5. Assert identity(n) is the multiplicative identity for n=1,2,3."""
    for n in (1, 2, 3):
        ident = Pauli.identity(n)
        assert ident.n == n
        assert ident.x == (0,) * n
        assert ident.z == (0,) * n
        assert ident.phase == 0

        # Sample Paulis of length n
        sample_letters = list(itertools.product("IXYZ", repeat=n))
        for letters in sample_letters:
            for token in ("+", "-", "+i", "-i"):
                p = Pauli.from_string(f"{token}{''.join(letters)}")
                assert p * ident == p, f"Right identity failed for {p}"
                assert ident * p == p, f"Left identity failed for {p}"


def test_multiplication_associativity() -> None:
    """Multiplication must be associative: (a * b) * c == a * (b * c)."""
    for n in (1, 2):
        letter_tuples = list(itertools.product("IXYZ", repeat=n))[:8]  # test over subset for n=2
        paulis = [Pauli.from_string("".join(letters)) for letters in letter_tuples]
        for a in paulis:
            for b in paulis:
                for c in paulis:
                    assert (a * b) * c == a * (b * c)


def test_weight_property() -> None:
    """Weight equals the number of non-identity qubit factors."""
    assert Pauli.from_string("IIII").weight() == 0
    assert Pauli.from_string("XIII").weight() == 1
    assert Pauli.from_string("XYZI").weight() == 3
    assert Pauli.from_string("-iYXYZ").weight() == 4


def test_conjugate_with_stim_tableau() -> None:
    """Check that conjugate(tableau, pauli) accurately computes C P C^dagger."""
    # 1-qubit Hadamard: H X H = Z, H Z H = X, H Y H = -Y
    t_h = stim.Tableau.from_circuit(stim.Circuit("H 0"))
    assert conjugate(t_h, Pauli.from_string("+X")) == Pauli.from_string("+Z")
    assert conjugate(t_h, Pauli.from_string("+Z")) == Pauli.from_string("+X")
    assert conjugate(t_h, Pauli.from_string("+Y")) == Pauli.from_string("-Y")

    # 1-qubit Phase gate S: S X S^dagger = Y, S Y S^dagger = -X, S Z S^dagger = Z
    t_s = stim.Tableau.from_circuit(stim.Circuit("S 0"))
    assert conjugate(t_s, Pauli.from_string("+X")) == Pauli.from_string("+Y")
    assert conjugate(t_s, Pauli.from_string("+Y")) == Pauli.from_string("-X")
    assert conjugate(t_s, Pauli.from_string("+Z")) == Pauli.from_string("+Z")

    # 2-qubit CNOT: CNOT (X I) CNOT = X X, CNOT (I Z) CNOT = Z Z
    t_cnot = stim.Tableau.from_circuit(stim.Circuit("CNOT 0 1"))
    assert conjugate(t_cnot, Pauli.from_string("+XI")) == Pauli.from_string("+XX")
    assert conjugate(t_cnot, Pauli.from_string("+IZ")) == Pauli.from_string("+ZZ")


def test_invalid_inputs_and_errors() -> None:
    """Ensure proper ValueErrors and TypeErrors are raised for invalid inputs."""
    with pytest.raises(ValueError, match="Invalid Pauli character"):
        Pauli.from_string("AB")

    with pytest.raises(ValueError, match="Length of x and z"):
        Pauli(n=2, x=(1,), z=(0, 0), phase=0)

    with pytest.raises(ValueError, match="must be 0 or 1"):
        Pauli(n=1, x=(2,), z=(0,), phase=0)

    p1 = Pauli.from_string("X")
    p2 = Pauli.from_string("XX")

    with pytest.raises(ValueError, match="different qubit counts"):
        _ = p1 * p2

    with pytest.raises(ValueError, match="different sizes"):
        _ = p1.commutes(p2)
