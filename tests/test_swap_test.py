"""Tests for the SWAP test verification counterpart (THE FIX DEMO).

PROVEN:
- A SWAP test between two identical normalised pure states accepts with probability 1.0
  (one-sided error / honest signature never falsely rejected).
- For a Pauli forgery U, single-copy detection probability is p = (1 - |<psi|U|psi>|^2)/2.
- Across k independent copies, detection probability is P_k = 1 - (1 - p)^k.
- For U = X on |0>, p = 0.5 and P_k = 1 - 2^-k.
- Monte Carlo simulations over 20,000 trials match analytic P_k to within 3 standard errors.
"""

from __future__ import annotations

import numpy as np
import pytest

from pauliguard.detectors.swap_test import (
    SwapTestVerdict,
    SwapTestVerifier,
    copies_needed,
    detection_probability_k_copies,
    swap_test_accept_probability,
    swap_test_detect_probability,
)
from pauliguard.engine.pauli import Pauli


def test_swap_test_accept_probability_honest_exact_one() -> None:
    """1. swap_test_accept_probability(psi, psi) == 1.0 exactly for several random normalised states.

    This is the one-sided-error property: an HONEST signature is NEVER falsely rejected.
    Assert exactly 1.0, not approximately.
    """
    rng = np.random.default_rng(20260831)

    # Test single-qubit basis states
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    psi_1 = np.array([0.0, 1.0], dtype=np.complex128)
    psi_plus = np.array([1.0, 1.0], dtype=np.complex128) / np.sqrt(2.0)

    assert swap_test_accept_probability(psi_0, psi_0) == 1.0
    assert swap_test_accept_probability(psi_1, psi_1) == 1.0
    assert swap_test_accept_probability(psi_plus, psi_plus) == 1.0

    # Test across multiple dimensions with random normalised states
    for dim in (2, 4, 8, 16):
        for _ in range(10):
            raw = rng.standard_normal(dim) + 1j * rng.standard_normal(dim)
            psi = raw / np.linalg.norm(raw)
            p_accept = swap_test_accept_probability(psi, psi)
            assert p_accept == 1.0, f"Expected exactly 1.0 for dim={dim}, got {p_accept}"

            # Also test passing a copy
            p_accept_copy = swap_test_accept_probability(psi, psi.copy())
            assert p_accept_copy == 1.0, f"Expected exactly 1.0 for copy dim={dim}, got {p_accept_copy}"


def test_swap_test_detect_probability_x_on_zero() -> None:
    """2. For psi = |0> and U = X, swap_test_detect_probability == 0.5 exactly."""
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    u_x = Pauli.from_string("X")
    p_detect = swap_test_detect_probability(psi_0, u_x)
    assert p_detect == 0.5, f"Expected p_detect == 0.5, got {p_detect}"


def test_swap_test_z_on_zero_no_power() -> None:
    """3. For psi = |0> and U = Z, <0|Z|0> = 1 so p_detect == 0.0 exactly,

    no_power is True, and copies_needed returns -1.
    """
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    u_z = Pauli.from_string("Z")

    p_detect = swap_test_detect_probability(psi_0, u_z)
    assert p_detect == 0.0, f"Expected p_detect == 0.0, got {p_detect}"

    verifier = SwapTestVerifier(k_copies=4)
    verdict = verifier.verify(psi_0, u_z)
    assert verdict.p_detect_single == 0.0
    assert verdict.p_detect_k == 0.0
    assert verdict.no_power is True

    # Z does not change the computational-basis message, so there is nothing
    # for the SWAP test to find. This is correct, not a failure.
    k_needed = copies_needed(psi_0, u_z, target_confidence=0.99)
    assert k_needed == -1, f"Expected copies_needed == -1 when no power, got {k_needed}"


def test_detection_probability_k_copies_closed_form() -> None:
    """4. detection_probability_k_copies for psi=|0>, U=X equals 1 - 2**-k exactly for k in 1..10.

    Assert the closed form, e.g. k=1 -> 0.5, k=4 -> 0.9375, k=10 -> 0.9990234375.
    """
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    u_x = Pauli.from_string("X")

    for k in range(1, 11):
        p_k = detection_probability_k_copies(psi_0, u_x, k)
        expected = 1.0 - (2.0 ** (-k))
        assert p_k == expected, f"For k={k}, expected {expected}, got {p_k}"

    assert detection_probability_k_copies(psi_0, u_x, 1) == 0.5
    assert detection_probability_k_copies(psi_0, u_x, 4) == 0.9375
    assert detection_probability_k_copies(psi_0, u_x, 10) == 0.9990234375


def test_headline_fix_monte_carlo_matches_analytic_bound() -> None:
    """5. THE HEADLINE FIX RESULT: Monte Carlo simulate() over 20000 trials must match the analytic

    detection_probability_k_copies to within 3 standard errors, for k in (1,2,4,8) and for
    U in (X, Y) on a computational-basis state. Report both numbers in the assertion message.
    """
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    trials = 20000

    for u_str in ("X", "Y"):
        u = Pauli.from_string(u_str)
        for k in (1, 2, 4, 8):
            verifier = SwapTestVerifier(k_copies=k, seed=1000 * k + (77 if u_str == "Y" else 33))
            empirical = verifier.simulate(psi_0, u, trials=trials)
            analytic = detection_probability_k_copies(psi_0, u, k)

            # Standard error of Bernoulli trial outcome fraction
            se = np.sqrt(analytic * (1.0 - analytic) / trials)
            tol = 3.0 * se
            diff = abs(empirical - analytic)

            assert diff <= tol, (
                f"Headline fix Monte Carlo simulation mismatch for U={u_str}, k={k}: "
                f"empirical={empirical:.6f}, analytic={analytic:.6f}, "
                f"diff={diff:.6f}, 3*SE={tol:.6f} (trials={trials})"
            )


def test_copies_needed_reaches_target() -> None:
    """6. copies_needed for psi=|0>, U=X at target 0.999 returns 10

    (since 1-2^-10 = 0.9990234375 >= 0.999, while 1-2^-9 = 0.998046875 < 0.999).
    Verify the returned k actually meets the target.
    """
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    u_x = Pauli.from_string("X")

    k = copies_needed(psi_0, u_x, target_confidence=0.999)
    assert k == 10, f"Expected k=10, got {k}"

    p_k = detection_probability_k_copies(psi_0, u_x, k)
    assert p_k >= 0.999, f"Computed k={k} gives p_k={p_k} < 0.999"

    p_k_prev = detection_probability_k_copies(psi_0, u_x, k - 1)
    assert p_k_prev < 0.999, f"Previous k={k-1} unexpectedly met target: p_k={p_k_prev}"


def test_multi_qubit_swap_test() -> None:
    """7. Multi-qubit: for a 2-qubit state |00> and U = X on qubit 0 (Pauli "XI"), p_detect == 0.5."""
    psi_00 = np.array([1.0, 0.0, 0.0, 0.0], dtype=np.complex128)
    u_xi = Pauli.from_string("XI")

    p_detect = swap_test_detect_probability(psi_00, u_xi)
    assert p_detect == 0.5, f"Expected multi-qubit p_detect == 0.5, got {p_detect}"

    verifier = SwapTestVerifier(k_copies=4)
    verdict = verifier.verify(psi_00, u_xi)
    assert verdict.p_detect_single == 0.5
    assert verdict.p_detect_k == 0.9375
    assert verdict.no_power is False
    assert verdict.detected is True


def test_verdict_derivation_string_populated() -> None:
    """8. Every verdict has a non-empty derivation string containing the actual numbers."""
    psi_0 = np.array([1.0, 0.0], dtype=np.complex128)
    for u_str in ("X", "Y", "Z", "I"):
        u = Pauli.from_string(u_str)
        verifier = SwapTestVerifier(k_copies=3)
        verdict = verifier.verify(psi_0, u)

        assert isinstance(verdict.derivation, str)
        assert len(verdict.derivation.strip()) > 0
        assert str(verdict.k_copies) in verdict.derivation
        assert f"{verdict.p_detect_single:.6f}" in verdict.derivation
        assert f"{verdict.p_detect_k:.6f}" in verdict.derivation
        assert f"{verdict.overlap:.6f}" in verdict.derivation
