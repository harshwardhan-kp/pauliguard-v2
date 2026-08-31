"""Paired Pauli forgery attack against Arbitrated Quantum Signature (AQS) schemes.

PROVEN:
- Step 1: V := E_k U E_k^dagger is again a Pauli operator, because E_k is a Clifford unitary.
- Step 2: E_k (U|P>) = (E_k U E_k^dagger)(E_k|P>) = V (E_k|P>) = V|S>. Thus the arbitrator
  verification predicate E_k |P'> == |S'> is satisfied identically with probability 1.0
  for every key, message state, and Pauli attack operator U.
- Step 3: Under QOTP, V equals U up to a sign factor (-1)^c only (the Pauli letters x and z
  are strictly invariant), and a global phase is physically unobservable.
- Step 4: Therefore decrypt(V . encrypt(|M><M|) . V^dagger) == U |M><M| U^dagger identically,
  so the forged execution produces the exact same density matrix as an honest execution on
  the modified message U|M>. No measurement whatsoever can distinguish them.

ASSUMED:
- The adversary has the capability to apply local unitary operations U to the message copy
  and V to the signature before presenting them to the arbitrator.
- The arbitrator verifies the predicate E_k|P> == |S> using standard projective verification
  (e.g., SWAP test or decryption-comparison) in the noiseless model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import numpy as np

from pauliguard.engine.encryption import Encryption, Key
from pauliguard.engine.pauli import Pauli


def _remove_global_phase(v: np.ndarray, atol: float = 1e-12) -> np.ndarray:
    """Normalize a state vector by dividing out the phase of its largest-magnitude component."""
    idx = int(np.argmax(np.abs(v)))
    mag = np.abs(v[idx])
    if mag < atol:
        return v
    phase_factor = v[idx] / mag
    return v / phase_factor


@dataclass
class ForgeryWitness:
    """Witness structure capturing the verification of a paired Pauli forgery attack.

    Fields:
      attack_pauli: The Pauli operator U applied to the message copy.
      signature_pauli: The conjugated Pauli operator V = E_k U E_k^dagger applied to the signature.
      key: The encryption key used by the arbitrator.
      n: Number of qubits.
      succeeds: True iff the arbitrator predicate is satisfied for the forged signature.
      sign_flipped: True iff V.phase != U.phase (e.g. anticommutation under QOTP).
      explanation: Human-readable explanation of the witness and verification result.
    """

    attack_pauli: Pauli
    signature_pauli: Pauli
    key: Any
    n: int
    succeeds: bool
    sign_flipped: bool
    explanation: str


def step1_clifford_conjugate_is_pauli(enc: Encryption, key: Any, n: int, U: Pauli) -> Pauli:
    """Step 1: Compute V = E_k U E_k^dagger and verify that V is a valid Pauli operator.

    Since E_k belongs to the Clifford group, it maps the Pauli group to itself under conjugation.
    """
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")
    V = enc.conjugate_attack(key, n, U)
    if not isinstance(V, Pauli):
        raise TypeError(f"Conjugation under Clifford must produce a Pauli instance, got {type(V)}")
    return V


def predicate_holds(
    enc: Encryption,
    key: Any,
    n: int,
    U: Pauli,
    message_state: np.ndarray,
) -> bool:
    """Step 2: Check whether the arbitrator verification predicate holds for a paired Pauli attack.

    message_state is a normalised numpy complex vector of length 2**n. Build E_k as a matrix
    via enc.tableau(key,n).to_unitary_matrix(endian="big"). Compute LHS = E_k @ (U_matrix @
    message_state) and RHS = V_matrix @ (E_k @ message_state). Return True iff LHS and RHS are
    equal UP TO GLOBAL PHASE (compare after dividing out the phase of the largest-magnitude
    component), tolerance 1e-9.
    """
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")

    msg_vec = np.asarray(message_state, dtype=np.complex128).ravel()
    if len(msg_vec) != 2**n:
        raise ValueError(f"message_state length {len(msg_vec)} does not match 2**n={2**n}")

    V = step1_clifford_conjugate_is_pauli(enc, key, n, U)

    tab = enc.tableau(key, n)
    E_k = tab.to_unitary_matrix(endian="big")

    U_matrix = U.to_matrix()
    V_matrix = V.to_matrix()

    LHS = E_k @ (U_matrix @ msg_vec)
    RHS = V_matrix @ (E_k @ msg_vec)

    lhs_canonical = _remove_global_phase(LHS)
    rhs_canonical = _remove_global_phase(RHS)

    diff = np.max(np.abs(lhs_canonical - rhs_canonical))
    return bool(diff < 1e-9)


step2_predicate_holds = predicate_holds


def step3_qotp_letters_preserved(enc: Encryption, key: Any, n: int, U: Pauli) -> bool:
    """Step 3: Verify that under QOTP, V equals U up to a sign only (Pauli letters preserved)."""
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")
    V = step1_clifford_conjugate_is_pauli(enc, key, n, U)
    return (V.x == U.x) and (V.z == U.z)


def forged_and_honest_density_matrices(
    enc: Encryption,
    key: Any,
    n: int,
    message_state: np.ndarray,
    U: Pauli,
) -> tuple[np.ndarray, np.ndarray]:
    """Step 4: Compute density matrices for forged and honest executions on the modified message.

    Returns (rho_forged, rho_honest_on_modified_message) where:
      rho_forged  = decrypt( V . encrypt(|M><M|) . V^dag )   with encrypt(.) = E_k . E_k^dag
      rho_honest  = U |M><M| U^dag
    These must be EQUAL. Return both so a test can assert it.
    """
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")

    msg_vec = np.asarray(message_state, dtype=np.complex128).ravel()
    if len(msg_vec) != 2**n:
        raise ValueError(f"message_state length {len(msg_vec)} does not match 2**n={2**n}")

    # Build pure density matrix |M><M|
    rho_m = np.outer(msg_vec, msg_vec.conj())

    # Build unitary matrix E_k
    tab = enc.tableau(key, n)
    E_k = tab.to_unitary_matrix(endian="big")
    E_k_dag = E_k.conj().T

    # Compute V = E_k U E_k^dagger
    V = step1_clifford_conjugate_is_pauli(enc, key, n, U)
    V_mat = V.to_matrix()
    V_mat_dag = V_mat.conj().T

    # encrypt(|M><M|) = E_k @ rho_m @ E_k_dag
    encrypted_rho = E_k @ rho_m @ E_k_dag

    # Adversary applies V to signature: V @ encrypted_rho @ V_dag
    forged_encrypted_rho = V_mat @ encrypted_rho @ V_mat_dag

    # decrypt(...) = E_k_dag @ forged_encrypted_rho @ E_k
    rho_forged = E_k_dag @ forged_encrypted_rho @ E_k

    # Honest execution on modified message U|M>: U @ rho_m @ U^dag
    U_mat = U.to_matrix()
    U_mat_dag = U_mat.conj().T
    rho_honest = U_mat @ rho_m @ U_mat_dag

    return rho_forged, rho_honest


step4_density_matrices = forged_and_honest_density_matrices


def paired_pauli_attack(
    enc: Encryption,
    key: Any,
    n: int,
    U: Pauli,
    message_state: np.ndarray | None = None,
) -> ForgeryWitness:
    """Execute and computationally verify a paired Pauli attack.

    Computes V = enc.conjugate_attack(key,n,U); sets succeeds by ACTUALLY CHECKING
    predicate_holds, not by assuming it. sign_flipped is V.phase != U.phase.
    """
    if U.n != n:
        raise ValueError(f"Pauli operator qubit count {U.n} does not match n={n}")

    V = step1_clifford_conjugate_is_pauli(enc, key, n, U)
    sign_flipped = (V.phase % 4) != (U.phase % 4)

    if message_state is not None:
        succeeds = predicate_holds(enc, key, n, U, message_state)
    else:
        # Check predicate across multiple canonical probe states
        test_states = [
            np.eye(2**n, dtype=np.complex128)[0],  # |0...0>
            np.ones(2**n, dtype=np.complex128) / np.sqrt(2**n),  # |+...+>
        ]
        succeeds = all(predicate_holds(enc, key, n, U, st) for st in test_states)

    explanation = (
        f"Paired Pauli attack on {enc.name} (n={n}, key={key}): "
        f"applied U={U.to_string()} to message copy and V={V.to_string()} to signature. "
        f"Arbitrator predicate holds={succeeds}, sign_flipped={sign_flipped}."
    )

    return ForgeryWitness(
        attack_pauli=U,
        signature_pauli=V,
        key=key,
        n=n,
        succeeds=succeeds,
        sign_flipped=sign_flipped,
        explanation=explanation,
    )
