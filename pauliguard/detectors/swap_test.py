"""SWAP Test Verification Counterpart — THE FIX DEMO.

WHY THIS EXISTS:
Every other layer in PauliGuard reports that the paired-Pauli forgery is invisible.
This module is the counterpart: it shows the attack DISAPPEARING when the protocol
is repaired. The repair is a SWAP test across multiple copies during verification.
This turns a defensive answer ("we cannot detect it") into an offensive one ("here
is the fix, and here is the attack rate collapsing to exactly the predicted bound").

THE MATHEMATICS:
A SWAP test on two states |psi> and |phi> ACCEPTS with probability (1 + |<psi|phi>|^2)/2.
It therefore DETECTS a difference with probability (1 - |<psi|phi>|^2)/2.
Under a Pauli attack U the verifier compares |psi> against U|psi>, so a SINGLE SWAP test
detects the forgery with probability
    p_detect = (1 - |<psi|U|psi>|^2) / 2
Across k INDEPENDENT copies the detection probability is
    P_k = 1 - (1 - p_detect)^k
For U = X acting on |0>, <0|X|0> = 0, so p_detect = 0.5 exactly and P_k = 1 - 2^-k.

HONEST LIMITATION:
If <psi|U|psi> = 1 the SWAP test has NO power (p_detect = 0), because U stabilises
the state and the message is not actually changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import numpy as np

from pauliguard.engine.pauli import Pauli


def swap_test_accept_probability(psi: np.ndarray, phi: np.ndarray) -> float:
    """(1 + |<psi|phi>|^2)/2 for two normalised complex numpy vectors.

    One-sided error property: when phi == psi (honest state), the accept
    probability is EXACTLY 1.0.
    """
    psi_arr = np.asarray(psi, dtype=np.complex128)
    phi_arr = np.asarray(phi, dtype=np.complex128)

    if psi is phi or np.array_equal(psi_arr, phi_arr):
        return 1.0

    inner_prod = np.vdot(psi_arr, phi_arr)
    overlap_sq = float(np.abs(inner_prod) ** 2)

    if np.isclose(overlap_sq, 1.0, atol=1e-12):
        overlap_sq = 1.0
    elif np.isclose(overlap_sq, 0.0, atol=1e-15):
        overlap_sq = 0.0

    overlap_sq = min(1.0, max(0.0, overlap_sq))
    return (1.0 + overlap_sq) / 2.0


def swap_test_detect_probability(psi: np.ndarray, U: Pauli) -> float:
    """(1 - |<psi|U|psi>|^2)/2 where U is a Pauli. Build U.to_matrix() to apply it."""
    psi_arr = np.asarray(psi, dtype=np.complex128)
    u_mat = U.to_matrix()
    u_psi = u_mat @ psi_arr

    overlap = np.vdot(psi_arr, u_psi)
    overlap_sq = float(np.abs(overlap) ** 2)

    if np.isclose(overlap_sq, 1.0, atol=1e-12):
        overlap_sq = 1.0
    elif np.isclose(overlap_sq, 0.0, atol=1e-15):
        overlap_sq = 0.0

    overlap_sq = min(1.0, max(0.0, overlap_sq))
    p_detect = (1.0 - overlap_sq) / 2.0

    if np.isclose(p_detect, 0.5, atol=1e-15):
        return 0.5
    if np.isclose(p_detect, 0.0, atol=1e-15):
        return 0.0

    return p_detect


def detection_probability_k_copies(psi: np.ndarray, U: Pauli, k: int) -> float:
    """1 - (1 - p)^k across k independent copies."""
    if k <= 0:
        return 0.0
    p = swap_test_detect_probability(psi, U)
    if p == 0.0:
        return 0.0
    if p == 0.5:
        return 1.0 - (2.0 ** (-k))
    return 1.0 - ((1.0 - p) ** k)


def copies_needed(psi: np.ndarray, U: Pauli, target_confidence: float) -> int:
    """Smallest k with detection_probability_k_copies >= target_confidence.

    Return -1 (and do NOT loop forever) when p_detect == 0, i.e. when the SWAP test
    has no power against that U.
    """
    p = swap_test_detect_probability(psi, U)
    if p <= 0.0:
        return -1
    if target_confidence <= 0.0:
        return 1

    k = 1
    while k < 100000:
        p_k = detection_probability_k_copies(psi, U, k)
        if p_k >= target_confidence:
            return k
        k += 1

    return -1


@dataclass
class SwapTestVerdict:
    detected: bool
    p_detect_single: float
    p_detect_k: float
    k_copies: int
    overlap: float                 # |<psi|U|psi>|
    derivation: str                # named formula with the actual numbers substituted
    no_power: bool                 # True iff p_detect_single == 0


class SwapTestVerifier:
    def __init__(self, k_copies: int, seed: int | None = None) -> None:
        if k_copies <= 0:
            raise ValueError(f"k_copies must be positive, got {k_copies}")
        self.k_copies = k_copies
        self.rng = np.random.default_rng(seed)

    def verify(self, psi: np.ndarray, U: Pauli) -> SwapTestVerdict:
        """Analytic evaluation of SWAP test verification across k copies."""
        psi_arr = np.asarray(psi, dtype=np.complex128)
        u_mat = U.to_matrix()
        u_psi = u_mat @ psi_arr

        overlap_val = np.vdot(psi_arr, u_psi)
        overlap = float(np.abs(overlap_val))
        overlap_sq = overlap ** 2
        if np.isclose(overlap_sq, 1.0, atol=1e-12):
            overlap = 1.0
            overlap_sq = 1.0
        elif np.isclose(overlap_sq, 0.0, atol=1e-15):
            overlap = 0.0
            overlap_sq = 0.0

        p_single = swap_test_detect_probability(psi_arr, U)
        p_k = detection_probability_k_copies(psi_arr, U, self.k_copies)

        no_power = (p_single == 0.0)
        detected = (not no_power) and (self.k_copies > 0)

        derivation = (
            f"|<psi|U|psi>| = {overlap:.6f}; "
            f"p_detect_single = (1 - |<psi|U|psi>|^2)/2 = (1 - {overlap:.6f}^2)/2 = {p_single:.6f}; "
            f"P_{self.k_copies} = 1 - (1 - p_detect_single)^{self.k_copies} = "
            f"1 - (1 - {p_single:.6f})^{self.k_copies} = {p_k:.6f}"
        )

        return SwapTestVerdict(
            detected=detected,
            p_detect_single=p_single,
            p_detect_k=p_k,
            k_copies=self.k_copies,
            overlap=overlap,
            derivation=derivation,
            no_power=no_power,
        )

    def simulate(self, psi: np.ndarray, U: Pauli, trials: int) -> float:
        """MONTE CARLO simulation.

        For each trial run k independent Bernoulli draws at p_detect_single and
        report the empirical detection fraction. This is what must MATCH the analytic bound.
        """
        if trials <= 0:
            return 0.0
        p_single = swap_test_detect_probability(psi, U)
        if p_single == 0.0:
            return 0.0

        # Each copy detects with probability p_single independently.
        # A trial detects if AT LEAST ONE of the k copies detects the attack.
        draws = self.rng.random((trials, self.k_copies)) < p_single
        trial_detected = np.any(draws, axis=1)
        return float(np.mean(trial_detected))
