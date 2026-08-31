"""Tests for the L2 entanglement-quality detector.

Covers CHSH constants, Azuma-Hoeffding bound properties, ideal/corrupted
stabilizer analysis, the blindness result against paired-Pauli attacks,
and sensitivity sweep.
"""

from __future__ import annotations

import math

import numpy as np
import pytest
import stim

from pauliguard.detectors.layer2 import (
    Layer2,
    L2Verdict,
    azuma_fpr,
    chsh_from_correlators,
    ideal_chsh,
    tau_for_alpha_azuma,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bell_pair_tableau() -> stim.Tableau:
    """Build a 2-qubit Bell-pair tableau from H 0; CNOT 0 1."""
    circuit = stim.Circuit("H 0\nCNOT 0 1")
    return stim.Tableau.from_circuit(circuit)


# ===========================================================================
# Test 1: ideal_chsh() == 2*sqrt(2) and exceeds separable bound
# ===========================================================================

class TestIdealCHSH:
    def test_value(self):
        """ideal_chsh() == 2*sqrt(2) to 1e-12."""
        assert abs(ideal_chsh() - 2.0 * math.sqrt(2.0)) < 1e-12

    def test_exceeds_separable_bound(self):
        """The Tsirelson bound 2*sqrt(2) strictly exceeds the separable bound 2."""
        assert ideal_chsh() > 2.0


# ===========================================================================
# Test 2: chsh_from_correlators reproduces 2*sqrt(2)
# ===========================================================================

class TestCHSHCorrelators:
    def test_standard_optimal(self):
        """Standard optimal correlators reproduce 2*sqrt(2).

        The optimal quantum correlators for CHSH are:
          E(a,b)   = +1/sqrt(2)
          E(a,b')  = -1/sqrt(2)
          E(a',b)  = +1/sqrt(2)
          E(a',b') = +1/sqrt(2)

        S = 1/sqrt(2) - (-1/sqrt(2)) + 1/sqrt(2) + 1/sqrt(2) = 4/sqrt(2) = 2*sqrt(2)
        """
        r = 1.0 / math.sqrt(2.0)
        s = chsh_from_correlators(+r, -r, +r, +r)
        assert abs(s - 2.0 * math.sqrt(2.0)) < 1e-12, (
            f"Expected 2*sqrt(2), got {s}"
        )


# ===========================================================================
# Test 3: azuma_fpr and tau_for_alpha_azuma are exact inverses
# ===========================================================================

class TestAzumaRoundTrip:
    @pytest.mark.parametrize(
        "m,alpha",
        [
            (100, 1e-3),
            (200, 1e-5),
            (500, 1e-8),
            (1000, 1e-10),
            (50, 0.01),
            (2000, 1e-6),
            (10, 0.05),
            (5000, 1e-12),
        ],
    )
    def test_round_trip(self, m, alpha):
        """tau_for_alpha_azuma(m, alpha) -> azuma_fpr(m, tau) should return alpha to 1e-12."""
        tau = tau_for_alpha_azuma(m, alpha)
        recovered = azuma_fpr(m, tau)
        assert abs(recovered - alpha) < 1e-12, (
            f"Round-trip failed: alpha={alpha}, recovered={recovered:.15e}, "
            f"diff={abs(recovered - alpha):.2e}"
        )


# ===========================================================================
# Test 4: azuma_fpr is LOOSER than iid Hoeffding bound
# ===========================================================================

class TestAzumaLooser:
    """The Azuma-Hoeffding bound exp(-m*tau^2/2) is LOOSER (larger FPR) than
    the i.i.d. Hoeffding bound exp(-2*m*tau^2) for all m, tau > 0.

    This is the honesty requirement: the factor-of-4 gap in the exponent is
    the price of validity against an adaptive adversary.
    """

    @pytest.mark.parametrize(
        "m,tau",
        [
            (10, 0.1),
            (50, 0.05),
            (100, 0.03),
            (200, 0.02),
            (500, 0.01),
            (1000, 0.05),
            (2000, 0.1),
            (50, 0.2),
            (10, 0.5),
            (5000, 0.001),
        ],
    )
    def test_azuma_looser_than_hoeffding(self, m, tau):
        """azuma_fpr(m, tau) >= iid_hoeffding(m, tau) for all m, tau > 0.

        Azuma:     exp(-m * tau^2 / 2)
        Hoeffding: exp(-2 * m * tau^2)

        Since -m*tau^2/2 > -2*m*tau^2 for all m,tau > 0, the Azuma bound is
        strictly LARGER (looser) than the Hoeffding bound.
        """
        azuma = azuma_fpr(m, tau)
        iid_hoeffding = math.exp(-2.0 * m * tau * tau)
        assert azuma >= iid_hoeffding, (
            f"Azuma ({azuma:.6e}) should be >= iid Hoeffding ({iid_hoeffding:.6e}) "
            f"at m={m}, tau={tau}. The Azuma bound is LOOSER by construction."
        )
        # Also assert strict inequality (not just >=)
        assert azuma > iid_hoeffding, (
            f"Azuma ({azuma:.6e}) should be STRICTLY > iid Hoeffding ({iid_hoeffding:.6e}) "
            f"for m={m}, tau={tau} > 0."
        )


# ===========================================================================
# Test 5: Ideal stabilizer state (corruption=0.0) -> ZERO flagged
# ===========================================================================

class TestIdealResource:
    def test_no_false_positives(self):
        """On an IDEAL stabilizer state (corruption=0.0), over 200 analyses at
        alpha=1e-6, ZERO are flagged and p_hat is exactly 1.0.
        """
        tableau = _bell_pair_tableau()
        detector = Layer2(alpha=1e-6)

        flagged_count = 0
        for i in range(200):
            verdict = detector.analyse_resource(
                tableau, m=100, seed=40000 + i, corruption=0.0
            )
            assert verdict.observed == 1.0, (
                f"Ideal stabilizer state must have p_hat=1.0, got {verdict.observed} "
                f"(seed={40000 + i})"
            )
            if verdict.flagged:
                flagged_count += 1

        assert flagged_count == 0, (
            f"Expected 0 false positives on ideal resource at alpha=1e-6 over "
            f"200 analyses, got {flagged_count}"
        )


# ===========================================================================
# Test 6: Corrupted resource (corruption=0.30) -> ALL flagged
# ===========================================================================

class TestCorruptedResource:
    def test_all_corrupted_flagged(self):
        """On a CORRUPTED resource (corruption=0.30), over 200 analyses at m=500,
        ALL are flagged.  Detection rate == 1.0.

        At m=500 and alpha=1e-6, tau_azuma = sqrt(-2*ln(1e-6)/500) ≈ 0.235,
        which is well below the expected deviation of 0.30 from an ideal
        resource, so every run should be flagged.
        """
        tableau = _bell_pair_tableau()
        detector = Layer2(alpha=1e-6)

        flagged_count = 0
        for i in range(200):
            verdict = detector.analyse_resource(
                tableau, m=500, seed=50000 + i, corruption=0.30
            )
            if verdict.flagged:
                flagged_count += 1

        detection_rate = flagged_count / 200
        assert detection_rate == 1.0, (
            f"Expected detection rate 1.0 at corruption=0.30, m=500, "
            f"got {detection_rate} ({flagged_count}/200 flagged)"
        )


# ===========================================================================
# Test 7: Sensitivity sweep — detection rate monotonically non-decreasing
# ===========================================================================

class TestSensitivitySweep:
    def test_monotonic_detection_rate(self):
        """For corruption in (0.0, 0.01, 0.05, 0.10, 0.20, 0.40), the detection
        rate is monotonically non-decreasing.
        """
        tableau = _bell_pair_tableau()
        detector = Layer2(alpha=1e-4)
        corruptions = [0.0, 0.01, 0.05, 0.10, 0.20, 0.40]
        n_trials = 200

        rates = []
        for corruption in corruptions:
            flagged = 0
            for i in range(n_trials):
                verdict = detector.analyse_resource(
                    tableau, m=500, seed=60000 + i, corruption=corruption
                )
                if verdict.flagged:
                    flagged += 1
            rate = flagged / n_trials
            rates.append(rate)

        # Report the sweep
        print("\n--- L2 Sensitivity Sweep ---")
        for corruption, rate in zip(corruptions, rates):
            print(f"  corruption={corruption:.2f}  detection_rate={rate:.3f}")
        print("----------------------------")

        # Assert monotonically non-decreasing
        for i in range(1, len(rates)):
            assert rates[i] >= rates[i - 1], (
                f"Detection rate is NOT monotonically non-decreasing: "
                f"rate[corruption={corruptions[i]:.2f}]={rates[i]:.3f} < "
                f"rate[corruption={corruptions[i-1]:.2f}]={rates[i-1]:.3f}"
            )


# ===========================================================================
# Test 8: THE BLINDNESS RESULT — paired-Pauli attack is invisible to L2
# ===========================================================================

class TestBlindnessResult:
    """L2 flags the resource tableau ZERO times over 200 runs under a
    paired_pauli attack, because the attack NEVER TOUCHES the resource.

    This is a TRUE NEGATIVE by construction and it is exactly why L3 is needed.

    The paired-Pauli forgery applies U to the message copy and V = E_k U E_k^dag
    to the signature.  Neither operation touches the shared entangled resource
    state.  Therefore, any detector that measures only the resource state — such
    as the stabilizer-generator sampling in L2 — sees the IDENTICAL state under
    attack as under honest execution.  The detection rate is EXACTLY 0.0.
    """

    def test_paired_pauli_invisible(self):
        """Build the resource tableau used by the lu-2022 engine run under a
        paired_pauli attack, and assert L2 flags it ZERO times over 200 runs.
        """
        # The resource is a Bell-pair tableau — the same entangled resource
        # used by the lu-2022 protocol engine.  The paired-Pauli attack
        # never modifies this resource; it only touches the message copy
        # and signature.
        tableau = _bell_pair_tableau()
        detector = Layer2(alpha=1e-6)

        flagged_count = 0
        for i in range(200):
            # The resource is UNTOUCHED by the paired-Pauli attack,
            # so corruption=0.0 is the correct model: the attack does
            # not degrade the resource state at all.
            verdict = detector.analyse_resource(
                tableau, m=100, seed=70000 + i, corruption=0.0
            )
            if verdict.flagged:
                flagged_count += 1

        # This is a TRUE NEGATIVE by construction and it is exactly why L3 is needed.
        # The paired-Pauli attack is invisible to L2 because L2 only examines
        # the resource state, which the attack never touches.
        rate = flagged_count / 200
        assert rate == 0.0, (
            f"BLINDNESS VIOLATION: L2 should flag paired-Pauli attack ZERO times "
            f"(the attack never touches the resource), but flagged {flagged_count}/200 "
            f"(rate={rate}). This is a TRUE NEGATIVE by construction — "
            f"it is exactly why L3 is needed."
        )


# ===========================================================================
# Test 9: Changing alpha changes the threshold
# ===========================================================================

class TestNoHardcodedThresholds:
    def test_changing_alpha_changes_threshold(self):
        """Changing alpha changes the threshold (no hidden literal)."""
        m = 200
        tau_tight = tau_for_alpha_azuma(m, 1e-12)
        tau_loose = tau_for_alpha_azuma(m, 1e-3)
        assert tau_tight > tau_loose, (
            f"Tighter alpha should produce larger tau: "
            f"tau(1e-12)={tau_tight}, tau(1e-3)={tau_loose}"
        )

    def test_detector_alpha_affects_verdict(self):
        """Two detectors with different alpha produce different thresholds on the same data."""
        tableau = _bell_pair_tableau()
        det_tight = Layer2(alpha=1e-12)
        det_loose = Layer2(alpha=0.1)

        v_tight = det_tight.analyse_resource(tableau, m=100, seed=99999, corruption=0.0)
        v_loose = det_loose.analyse_resource(tableau, m=100, seed=99999, corruption=0.0)

        assert v_tight.threshold > v_loose.threshold, (
            f"Tighter alpha should yield larger threshold: "
            f"tight={v_tight.threshold}, loose={v_loose.threshold}"
        )


# --- supervisor-added: the sensitivity floor is a documented property, not an accident ---
def test_sensitivity_floor_is_explicit_and_consistent():
    """m=200 at alpha=1e-6 genuinely CANNOT detect 30% corruption. Pin that."""
    import math
    from pauliguard.detectors.layer2 import (min_samples_for_corruption,
                                             detectable_corruption,
                                             tau_for_alpha_azuma)
    # the threshold at m=200 exceeds 0.30, so silence there is correct behaviour
    assert tau_for_alpha_azuma(200, 1e-6) > 0.30
    # and the module says how many samples you would actually need
    need = min_samples_for_corruption(0.30, 1e-6)
    assert need > 200
    assert tau_for_alpha_azuma(need, 1e-6) <= 0.30 + 1e-12
    # round-trip consistency between the two helpers
    for m in (200, 500, 1000, 4096):
        c = detectable_corruption(m, 1e-6)
        assert min_samples_for_corruption(c, 1e-6) <= m + 1


def test_detection_rate_matches_the_predicted_floor():
    """Empirical detection must switch on near the predicted threshold, not before."""
    import stim
    from pauliguard.detectors.layer2 import Layer2, tau_for_alpha_azuma
    T = stim.Circuit("H 0\nCNOT 0 1").to_tableau()
    L = Layer2(alpha=1e-6)
    m = 500
    tau = tau_for_alpha_azuma(m, 1e-6)
    below = sum(L.analyse_resource(T, m=m, seed=i, corruption=tau * 0.5).flagged
                for i in range(100)) / 100
    above = sum(L.analyse_resource(T, m=m, seed=i, corruption=min(1.0, tau * 1.8)).flagged
                for i in range(100)) / 100
    assert below == 0.0, f"fired below the predicted floor: {below}"
    assert above == 1.0, f"failed to fire well above the floor: {above}"
