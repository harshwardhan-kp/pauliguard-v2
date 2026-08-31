"""Comprehensive computational verification of the central headline claim.

THE SCIENTIFIC CLAIM:
An adversary in an Arbitrated Quantum Signature (AQS) scheme who applies a Pauli operator U
to the message copy and V = E_k U E_k^dagger to the signature succeeds with PROBABILITY EXACTLY 1.0
in satisfying the arbitrator predicate E_k |P> == |S> across all keys, without knowing the key.
Furthermore, under QOTP encryption, the resulting forged state is physically indistinguishable
from an honest execution on the modified message U|M>, producing the exact same density matrix.

PROVEN:
- Step 1: V = E_k U E_k^dagger is always a Pauli operator for any Clifford encryption E_k.
- Step 2: E_k (U|P>) = V (E_k|P>) identically up to global phase; the arbitrator predicate
  holds for EVERY key in the keyspace and EVERY message state.
- Step 3: For QOTP, V has identical Pauli letters to U (x and z bit vectors are invariant),
  differing only by a global sign factor (-1)^c.
- Step 4: The decrypted forged state decrypt(V . encrypt(|M><M|) . V^dagger) is mathematically
  identical to U |M><M| U^dagger (trace distance 0, max matrix diff < 1e-12).

ASSUMED:
- Noiseless quantum state transmission and ideal projective verification by the arbitrator.
"""

from __future__ import annotations

import itertools
import numpy as np
import pytest

from pauliguard.attacks.paired_pauli import (
    ForgeryWitness,
    forged_and_honest_density_matrices,
    paired_pauli_attack,
    predicate_holds,
    step1_clifford_conjugate_is_pauli,
    step2_predicate_holds,
    step3_qotp_letters_preserved,
    step4_density_matrices,
)
from pauliguard.engine.encryption import ChainedCNOT, QOTP
from pauliguard.engine.pauli import Pauli


def _remove_global_phase(v: np.ndarray, atol: float = 1e-12) -> np.ndarray:
    """Normalize a state vector by dividing out the phase of its largest-magnitude component."""
    idx = int(np.argmax(np.abs(v)))
    mag = np.abs(v[idx])
    if mag < atol:
        return v
    phase_factor = v[idx] / mag
    return v / phase_factor


def _generate_test_states(n: int) -> list[np.ndarray]:
    """Generate at least 4 distinct normalized test states for n qubits.

    Includes:
      1. Computational basis state |0...0>
      2. Computational basis state |1...1>
      3. Equal superposition state |+...+> = sum_x |x> / sqrt(2^n)
      4. Deterministic random normalized complex state
    """
    dim = 2**n
    # 1. |0...0>
    st_0 = np.eye(dim, dtype=np.complex128)[0]

    # 2. |1...1>
    st_1 = np.eye(dim, dtype=np.complex128)[-1]

    # 3. Equal superposition state |+...+>
    st_plus = np.ones(dim, dtype=np.complex128) / np.sqrt(dim)

    # 4. Deterministic random normalized state
    rng = np.random.default_rng(seed=20260831 + n)
    raw = rng.standard_normal(dim) + 1j * rng.standard_normal(dim)
    st_rand = raw / np.linalg.norm(raw)

    return [st_0, st_1, st_plus, st_rand]


def _get_non_identity_paulis(n: int) -> list[Pauli]:
    """Enumerate all 4^n - 1 non-identity Pauli operators on n qubits."""
    letter_tuples = list(itertools.product("IXYZ", repeat=n))
    return [
        Pauli.from_string("".join(letters))
        for letters in letter_tuples
        if any(ch != "I" for ch in letters)
    ]


def test_headline_claim_predicate_holds_exhaustive() -> None:
    """Assertion 1: Exhaustive verification that predicate_holds is True for QOTP across

    n=1,2,3, EVERY key, EVERY non-identity Pauli U, and at least 4 different message states
    including a superposition state and a random normalised state.
    Reports the total count in the assertion message.
    """
    qotp = QOTP()
    total_evaluations = 0
    passed_evaluations = 0

    for n in (1, 2, 3):
        states = _generate_test_states(n)
        assert len(states) >= 4, f"Must test at least 4 states, got {len(states)}"

        non_id_paulis = _get_non_identity_paulis(n)
        assert len(non_id_paulis) == 4**n - 1

        keys = list(qotp.iter_keys(n))
        assert len(keys) == 4**n

        for key in keys:
            for u in non_id_paulis:
                for st in states:
                    holds = predicate_holds(qotp, key, n, u, st)
                    assert holds is True, (
                        f"Predicate failed for n={n}, key={key}, U={u.to_string()}"
                    )
                    total_evaluations += 1
                    passed_evaluations += 1

    # Expected count:
    # n=1: 4 keys * 3 Paulis * 4 states = 48
    # n=2: 16 keys * 15 Paulis * 4 states = 960
    # n=3: 64 keys * 63 Paulis * 4 states = 16,128
    # Total = 17,136
    expected_total = 17136
    assert total_evaluations == expected_total, (
        f"Expected {expected_total} total evaluations, executed {total_evaluations}"
    )
    assert passed_evaluations == total_evaluations, (
        f"Arbitrator predicate holds identically across all {passed_evaluations} verified evaluations "
        f"(n in {{1, 2, 3}}, every key, every non-identity Pauli U, 4 distinct message states)."
    )


def test_headline_claim_paired_attack_empirical_success_rate_one() -> None:
    """Assertion 2: Over that same sweep, the empirical success rate of paired_pauli_attack

    is EXACTLY 1.0 (assert == 1.0, not approx).
    """
    qotp = QOTP()
    total_attacks = 0
    successful_attacks = 0

    for n in (1, 2, 3):
        non_id_paulis = _get_non_identity_paulis(n)
        keys = list(qotp.iter_keys(n))

        for key in keys:
            for u in non_id_paulis:
                witness = paired_pauli_attack(qotp, key, n, u)
                assert isinstance(witness, ForgeryWitness)
                assert witness.attack_pauli == u
                assert witness.key == key
                assert witness.n == n

                total_attacks += 1
                if witness.succeeds:
                    successful_attacks += 1

    # Expected attack count:
    # n=1: 4 * 3 = 12
    # n=2: 16 * 15 = 240
    # n=3: 64 * 63 = 4032
    # Total = 4,284
    expected_attacks = 4284
    assert total_attacks == expected_attacks
    assert successful_attacks == total_attacks

    empirical_success_rate = successful_attacks / total_attacks
    assert empirical_success_rate == 1.0, (
        f"Empirical success rate must be EXACTLY 1.0, got {empirical_success_rate} "
        f"({successful_attacks}/{total_attacks})"
    )


def test_headline_claim_density_matrix_exact_equality() -> None:
    """Assertion 3: forged_and_honest_density_matrices returns two matrices equal to within

    1e-12, for QOTP, n=1,2, every key, several U and several message states.
    """
    qotp = QOTP()

    for n in (1, 2):
        states = _generate_test_states(n)
        non_id_paulis = _get_non_identity_paulis(n)
        keys = list(qotp.iter_keys(n))

        for key in keys:
            for u in non_id_paulis:
                for st in states:
                    rho_forged, rho_honest = forged_and_honest_density_matrices(
                        qotp, key, n, st, u
                    )
                    assert rho_forged.shape == (2**n, 2**n)
                    assert rho_honest.shape == (2**n, 2**n)

                    max_diff = float(np.max(np.abs(rho_forged - rho_honest)))
                    assert max_diff < 1e-12, (
                        f"Density matrix mismatch for n={n}, key={key}, U={u.to_string()}: "
                        f"max_diff = {max_diff}"
                    )


def test_headline_claim_unpaired_attack_fails_control() -> None:
    """Assertion 4: A CONTROL that must FAIL: an UNPAIRED attack (apply U to the message copy

    but leave the signature untouched) makes predicate_holds False for at least one key/U.
    Assert this is False at least once, so test 1 is not passing vacuously.
    """
    qotp = QOTP()
    unpaired_failures = 0
    unpaired_total = 0

    for n in (1, 2):
        # Use state |0...0> and test across all non-identity Paulis
        st_0 = np.eye(2**n, dtype=np.complex128)[0]
        non_id_paulis = _get_non_identity_paulis(n)
        keys = list(qotp.iter_keys(n))

        for key in keys:
            tab = qotp.tableau(key, n)
            E_k = tab.to_unitary_matrix(endian="big")
            # Unpaired: signature untouched means V = I
            I_mat = np.eye(2**n, dtype=np.complex128)

            for u in non_id_paulis:
                u_mat = u.to_matrix()
                lhs = E_k @ (u_mat @ st_0)
                rhs = I_mat @ (E_k @ st_0)

                lhs_c = _remove_global_phase(lhs)
                rhs_c = _remove_global_phase(rhs)
                diff = np.max(np.abs(lhs_c - rhs_c))
                holds = bool(diff < 1e-9)

                unpaired_total += 1
                if not holds:
                    unpaired_failures += 1

    # Assert that unpaired attack FAILS at least once (in fact, it fails on most combinations)
    assert unpaired_failures > 0, (
        f"Control failure check: unpaired attack was expected to fail, but succeeded everywhere! "
        f"({unpaired_failures}/{unpaired_total})"
    )

    # Concretely verify on n=1 that applying U=X to state |0> fails for EVERY key
    st_zero = np.array([1.0, 0.0], dtype=np.complex128)
    u_x = Pauli.from_string("X")
    for key in qotp.iter_keys(1):
        tab = qotp.tableau(key, 1)
        E_k = tab.to_unitary_matrix(endian="big")
        lhs = E_k @ (u_x.to_matrix() @ st_zero)
        rhs = E_k @ st_zero  # Signature left untouched
        diff = np.max(np.abs(_remove_global_phase(lhs) - _remove_global_phase(rhs)))
        assert diff > 0.5, (
            f"Unpaired attack with X on |0> must strongly fail, got diff {diff} on key {key}"
        )


def test_headline_claim_anticommuting_sign_flip() -> None:
    """Assertion 5: Assert that at least one (key,U) pair produces sign_flipped=True,

    so the anticommuting case is exercised.
    """
    qotp = QOTP()
    sign_flipped_count = 0
    total_pairs = 0

    for n in (1, 2, 3):
        non_id_paulis = _get_non_identity_paulis(n)
        keys = list(qotp.iter_keys(n))

        for key in keys:
            for u in non_id_paulis:
                witness = paired_pauli_attack(qotp, key, n, u)
                total_pairs += 1
                if witness.sign_flipped:
                    sign_flipped_count += 1

    assert sign_flipped_count > 0, (
        f"Expected anticommuting sign flips, but got 0 out of {total_pairs} pairs"
    )

    # For QOTP, over all keys for any non-identity Pauli, exactly half the keys anticommute
    assert sign_flipped_count == total_pairs // 2, (
        f"Expected exactly half of all pairs ({total_pairs // 2}) to flip sign, "
        f"got {sign_flipped_count}/{total_pairs}"
    )

    # Explicit concrete case: n=1, key=((1,), (0,)) [X gate], U=Z
    # X Z X^dagger = -Z -> sign flipped from + to -
    u_z = Pauli.from_string("Z")
    key_x = ((1,), (0,))
    concrete_witness = paired_pauli_attack(qotp, key_x, 1, u_z)
    assert concrete_witness.sign_flipped is True
    assert concrete_witness.signature_pauli.to_string() == "-Z"
    assert concrete_witness.succeeds is True


def test_proof_four_steps_verified_functions() -> None:
    """Explicit unit test for each of the four separate verified proof step functions."""
    qotp = QOTP()
    n = 2
    key = ((1, 0), (0, 1))
    u = Pauli.from_string("XZ")
    st = _generate_test_states(n)[2]  # Superposition state

    # Step 1: V = E_k U E_k^dagger is a valid Pauli
    v = step1_clifford_conjugate_is_pauli(qotp, key, n, u)
    assert isinstance(v, Pauli)
    assert v.n == n

    # Step 2: E_k (U|P>) = V|S> holds identically
    holds = step2_predicate_holds(qotp, key, n, u, st)
    assert holds is True

    # Step 3: Under QOTP, V equals U up to sign only (Pauli letters preserved)
    letters_preserved = step3_qotp_letters_preserved(qotp, key, n, u)
    assert letters_preserved is True

    # Step 3 contrast: Under ChainedCNOT, letters are NOT preserved for spreading Paulis
    cnot_enc = ChainedCNOT()
    cnot_letters_preserved = step3_qotp_letters_preserved(cnot_enc, ((0, 0), (0, 0)), 2, Pauli.from_string("XI"))
    assert cnot_letters_preserved is False

    # Step 4: Density matrices are strictly equal
    rho_f, rho_h = step4_density_matrices(qotp, key, n, st, u)
    assert np.max(np.abs(rho_f - rho_h)) < 1e-12
