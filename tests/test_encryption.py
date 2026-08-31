"""Tests for quantum encryption models (QOTP and ChainedCNOT) and Pauli conjugation.

Validates the fundamental security property:
1. QOTP preserves Pauli letters for all keys and non-identity Paulis (n=1,2,3).
2. Explicit numpy matrix conjugation matches Stim tableau conjugation to 1e-12 (n=1,2).
3. ChainedCNOT genuinely spreads Pauli letters, falsifying pauli_letters_preserved (contrast case).
4. Keyspace sizes strictly match iter_keys enumeration counts for n=1,2,3.
"""

from __future__ import annotations

import itertools
import numpy as np
import pytest

from pauliguard.engine.encryption import (
    ChainedCNOT,
    Encryption,
    QOTP,
    pauli_letters_preserved,
)
from pauliguard.engine.pauli import Pauli

# Explicit single-qubit elementary matrices for independent non-Stim validation
_MAT_I = np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.complex128)
_MAT_X = np.array([[0.0, 1.0], [1.0, 0.0]], dtype=np.complex128)
_MAT_Z = np.array([[1.0, 0.0], [0.0, -1.0]], dtype=np.complex128)
_MAT_XZ = np.array([[0.0, -1.0], [1.0, 0.0]], dtype=np.complex128)


def _explicit_single_qubit_op(a: int, b: int) -> np.ndarray:
    """Return explicit 2x2 matrix for X^a Z^b."""
    if a == 0 and b == 0:
        return _MAT_I
    if a == 1 and b == 0:
        return _MAT_X
    if a == 0 and b == 1:
        return _MAT_Z
    if a == 1 and b == 1:
        return _MAT_XZ
    raise ValueError(f"Invalid bits a={a}, b={b}")


def _explicit_qotp_matrix(a_tuple: tuple[int, ...], b_tuple: tuple[int, ...]) -> np.ndarray:
    """Construct E_k = prod_{i=0}^{n-1} X^{a_i} Z^{b_i} as explicit Kronecker product."""
    n = len(a_tuple)
    if n == 0:
        return np.array([[1.0 + 0.0j]], dtype=np.complex128)

    mat = _explicit_single_qubit_op(a_tuple[0], b_tuple[0])
    for i in range(1, n):
        mat = np.kron(mat, _explicit_single_qubit_op(a_tuple[i], b_tuple[i]))
    return mat


def test_qotp_pauli_letters_preserved() -> None:
    """1. For QOTP, for n=1,2,3, for EVERY key and EVERY non-identity Pauli U,

    the conjugated V has identical x and z vectors to U (only the phase may change).
    Verified via pauli_letters_preserved.
    """
    qotp = QOTP()
    for n in (1, 2, 3):
        # Generate all 4^n - 1 non-identity Paulis
        all_letter_tuples = list(itertools.product("IXYZ", repeat=n))
        non_identity_letters = [
            "".join(letters)
            for letters in all_letter_tuples
            if any(ch != "I" for ch in letters)
        ]
        assert len(non_identity_letters) == 4**n - 1

        for s in non_identity_letters:
            u = Pauli.from_string(s)
            assert pauli_letters_preserved(qotp, n, u) is True, (
                f"pauli_letters_preserved failed for QOTP on n={n}, U={s}"
            )

            # Also check directly across all keys that x and z are identical
            for key in qotp.iter_keys(n):
                v = qotp.conjugate_attack(key, n, u)
                assert v.x == u.x, (
                    f"X-vector mismatch for n={n}, key={key}, U={s}: {v.x} != {u.x}"
                )
                assert v.z == u.z, (
                    f"Z-vector mismatch for n={n}, key={key}, U={s}: {v.z} != {u.z}"
                )
                assert v.phase in (0, 1, 2, 3)


def test_qotp_explicit_matrix_agreement() -> None:
    """2. For QOTP, verify with EXPLICIT numpy matrices for n=1,2 and every key that

    E_k @ U_matrix @ E_k_dagger equals V.to_matrix() to 1e-12, where E_k is built
    as an explicit kron product without using Stim.
    """
    qotp = QOTP()
    for n in (1, 2):
        letter_tuples = list(itertools.product("IXYZ", repeat=n))
        all_paulis = [Pauli.from_string("".join(letters)) for letters in letter_tuples]

        for key in qotp.iter_keys(n):
            a_tuple, b_tuple = key
            e_k = _explicit_qotp_matrix(a_tuple, b_tuple)
            e_k_dag = e_k.conj().T

            for u in all_paulis:
                v = qotp.conjugate_attack(key, n, u)
                u_mat = u.to_matrix()
                v_mat = v.to_matrix()
                expected_mat = e_k @ u_mat @ e_k_dag

                max_diff = np.max(np.abs(expected_mat - v_mat))
                assert max_diff < 1e-12, (
                    f"Matrix mismatch for n={n}, key={key}, U={u.to_string()}: max diff {max_diff}"
                )


def test_chained_cnot_contrast_case() -> None:
    """3. For ChainedCNOT with n>=2, demonstrate that pauli_letters_preserved is FALSE

    for at least one U (the CNOT chain genuinely spreads Pauli letters).
    """
    cnot_enc = ChainedCNOT()

    # Test n=2: XI -> CNOT(0->1) spreads X from qubit 0 to qubit 1, producing XX
    u_n2 = Pauli.from_string("XI")
    assert pauli_letters_preserved(cnot_enc, 2, u_n2) is False

    # Verify concrete spreading for the zero key on n=2: XI becomes XX
    zero_key_n2 = ((0, 0), (0, 0))
    v_n2 = cnot_enc.conjugate_attack(zero_key_n2, 2, u_n2)
    assert v_n2.to_string() == "+XX"
    assert v_n2.x != u_n2.x or v_n2.z != u_n2.z

    # Test n=3: XII -> CNOT chain spreads X across all 3 qubits, producing XXX
    u_n3 = Pauli.from_string("XII")
    assert pauli_letters_preserved(cnot_enc, 3, u_n3) is False

    # Verify concrete spreading for the zero key on n=3: XII becomes XXX
    zero_key_n3 = ((0, 0, 0), (0, 0, 0))
    v_n3 = cnot_enc.conjugate_attack(zero_key_n3, 3, u_n3)
    assert v_n3.to_string() == "+XXX"
    assert v_n3.x != u_n3.x or v_n3.z != u_n3.z


def test_keyspace_size_matches_iter_keys() -> None:
    """4. keyspace_size matches the number of items iter_keys yields, for n=1,2,3."""
    schemes: list[Encryption] = [QOTP(), ChainedCNOT()]

    for enc in schemes:
        for n in (1, 2, 3):
            expected_size = 4**n
            assert enc.keyspace_size(n) == expected_size

            keys = list(enc.iter_keys(n))
            assert len(keys) == expected_size
            assert len(keys) == enc.keyspace_size(n)

            # Ensure all enumerated keys are unique
            unique_keys = set(keys)
            assert len(unique_keys) == expected_size


def test_encryption_metadata_and_properties() -> None:
    """Validate naming and inheritance properties."""
    qotp = QOTP()
    cnot = ChainedCNOT()

    assert isinstance(qotp, Encryption)
    assert isinstance(cnot, Encryption)
    assert qotp.name == "qotp"
    assert cnot.name == "chained-cnot"


def test_encryption_edge_cases_and_errors() -> None:
    """Validate error handling for invalid arguments and dimensions."""
    qotp = QOTP()

    with pytest.raises(ValueError, match="non-negative"):
        qotp.keyspace_size(-1)

    with pytest.raises(ValueError, match="non-negative"):
        list(qotp.iter_keys(-1))

    with pytest.raises(ValueError, match="Key bit tuples must have length"):
        qotp.tableau(((0,), (0, 0)), 2)

    with pytest.raises(ValueError, match="does not match"):
        qotp.conjugate_attack(((0,), (0,)), 1, Pauli.from_string("XX"))

    with pytest.raises(ValueError, match="does not match"):
        pauli_letters_preserved(qotp, 1, Pauli.from_string("XX"))
