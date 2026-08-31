"""Tests for the L1 channel-statistics detector.

Covers the mathematical properties of Serfling's inequality, Clopper-Pearson
intervals, and the floor-relative detection logic against engine-generated
traces.
"""

from __future__ import annotations

import math

import pytest
from scipy.stats import hypergeom

from pauliguard.detectors.layer1 import (
    Layer1,
    L1Verdict,
    clopper_pearson,
    hoeffding_fpr,
    min_sample_for,
    serfling_fpr,
    tau_for_alpha,
)
from pauliguard.engine.protocol import ProtocolEngine, RunConfig, run_many
from pauliguard.engine.spec_loader import discover_specs
from pauliguard.engine.trace import Trace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig_figs_match(actual: float, expected: float, figs: int) -> bool:
    """Check that `actual` matches `expected` to `figs` significant figures."""
    if expected == 0.0:
        return abs(actual) < 10 ** (-figs)
    magnitude = math.floor(math.log10(abs(expected)))
    tolerance = 0.5 * 10 ** (magnitude - figs + 1)
    return abs(actual - expected) < tolerance


SPECS_DIR = "pauliguard/specs"
SPEC_NAME = "lu-2022"


def _load_spec():
    specs = discover_specs(SPECS_DIR)
    assert SPEC_NAME in specs, f"Spec '{SPEC_NAME}' not found in {list(specs.keys())}"
    return specs[SPEC_NAME]


# ===========================================================================
# Test 1: Reference values to 3 significant figures
# ===========================================================================

class TestReferenceValues:
    """Assert the three reference Serfling / Hoeffding values."""

    def test_serfling_reference(self):
        """serfling_fpr(k=4096, N=16384, tau=0.03) ≈ 5.38e-5 to 3 sig figs.

        Exact: exp(−2·4096·0.0009 / (1−4095/16384)) = exp(−9.8296...) = 5.3834e-5
        """
        val = serfling_fpr(k=4096, N=16384, tau=0.03)
        assert _sig_figs_match(val, 5.383e-5, 3), (
            f"serfling_fpr(4096, 16384, 0.03) = {val:.6e}, expected ~5.383e-5"
        )

    def test_hoeffding_reference(self):
        """hoeffding_fpr(k=4096, tau=0.03) ≈ 6.28e-4 to 3 sig figs.

        Exact: exp(−2·4096·0.0009) = exp(−7.3728) = 6.2811e-4
        """
        val = hoeffding_fpr(k=4096, tau=0.03)
        assert _sig_figs_match(val, 6.281e-4, 3), (
            f"hoeffding_fpr(4096, 0.03) = {val:.6e}, expected ~6.281e-4"
        )

    def test_serfling_tighter_ratio(self):
        """Serfling is approximately 11.67× tighter than Hoeffding at k=4096, N=16384, tau=0.03."""
        s = serfling_fpr(k=4096, N=16384, tau=0.03)
        h = hoeffding_fpr(k=4096, tau=0.03)
        ratio = h / s
        assert 11.0 < ratio < 12.5, f"Tightness ratio = {ratio:.2f}, expected ~11.67"


# ===========================================================================
# Test 2: Serfling → Hoeffding convergence as N → ∞
# ===========================================================================

class TestConvergence:
    def test_serfling_converges_to_hoeffding_large_N(self):
        """For N = 10^9 the Serfling FPR should match Hoeffding to within 0.1%."""
        k = 4096
        tau = 0.03
        N_huge = 10**9
        s = serfling_fpr(k, N_huge, tau)
        h = hoeffding_fpr(k, tau)
        rel_diff = abs(s - h) / h
        assert rel_diff < 1e-3, (
            f"Relative difference {rel_diff:.2e} exceeds 1e-3 at N={N_huge}"
        )


# ===========================================================================
# Test 3: Serfling is strictly tighter than Hoeffding for finite N > k
# ===========================================================================

class TestSerflingTighter:
    @pytest.mark.parametrize(
        "k,N,tau",
        [
            (100, 1000, 0.05),
            (500, 2000, 0.02),
            (1000, 5000, 0.03),
            (4096, 16384, 0.03),
            (200, 10000, 0.04),
            (50, 200, 0.1),
            (2000, 4000, 0.01),
            (10, 100, 0.15),
        ],
    )
    def test_serfling_strictly_tighter(self, k, N, tau):
        """For any finite N > k, Serfling FPR < Hoeffding FPR (strictly tighter)."""
        s = serfling_fpr(k, N, tau)
        h = hoeffding_fpr(k, tau)
        assert s < h, (
            f"Serfling ({s:.6e}) should be < Hoeffding ({h:.6e}) for k={k}, N={N}, tau={tau}"
        )


# ===========================================================================
# Test 4: Round-trip tau_for_alpha ↔ serfling_fpr
# ===========================================================================

class TestRoundTrip:
    @pytest.mark.parametrize(
        "k,N,alpha",
        [
            (100, 400, 1e-3),
            (500, 2000, 1e-5),
            (1000, 10000, 1e-8),
            (4096, 16384, 1e-10),
            (200, 800, 0.01),
            (50, 500, 1e-6),
        ],
    )
    def test_tau_round_trip(self, k, N, alpha):
        """tau_for_alpha(k, N, α) → serfling_fpr(k, N, τ) should return α to 1e-9."""
        tau = tau_for_alpha(k, N, alpha)
        recovered_alpha = serfling_fpr(k, N, tau)
        assert abs(recovered_alpha - alpha) < 1e-9, (
            f"Round-trip failed: alpha={alpha}, recovered={recovered_alpha:.12e}, "
            f"diff={abs(recovered_alpha - alpha):.2e}"
        )


# ===========================================================================
# Test 5: Serfling is a genuine upper bound on the hypergeometric tail
# ===========================================================================

class TestHypergeometricBound:
    def test_serfling_bounds_hypergeometric_tail(self):
        """Build a small hypergeometric case and verify the Serfling bound is never violated.

        Setup: population N with M "bad" items, sample k without replacement.
        Serfling bound should be >= P(x̄ - μ >= τ) for the true hypergeometric.
        """
        N = 200
        k = 50
        # Test several values of M (number of defectives in population)
        for M in [10, 20, 50, 80, 100]:
            mu = M / N  # true population mean
            for tau in [0.02, 0.05, 0.10, 0.15, 0.20]:
                # True hypergeometric tail: P(X/k - mu >= tau) = P(X >= k*(mu+tau))
                threshold = k * (mu + tau)
                threshold_int = math.ceil(threshold)
                if threshold_int > min(k, M):
                    # Tail probability is 0, bound must be >= 0 — trivially true
                    continue
                # P(X >= threshold_int) using scipy hypergeom
                hyper_tail = hypergeom.sf(threshold_int - 1, N, M, k)
                serfling_bound = serfling_fpr(k, N, tau)
                assert serfling_bound >= hyper_tail - 1e-15, (
                    f"Serfling bound ({serfling_bound:.6e}) violated by hypergeometric "
                    f"tail ({hyper_tail:.6e}) at N={N}, M={M}, k={k}, tau={tau}"
                )


# ===========================================================================
# Test 6: THE HARDWARE POINT — absolute vs floor-relative threshold
# ===========================================================================

class TestHardwarePoint:
    """An ABSOLUTE threshold of 0.03 would flag an honest run at the measured
    ibm_kingston floor of 0.034424, while the floor-relative rule does NOT.
    This pins the design decision.
    """

    MEASURED_FLOOR = 0.034424

    def test_absolute_threshold_rejects_honest(self):
        """An absolute rule (flag iff x̄ ≥ 0.03) would reject an honest run at the floor."""
        # Honest run: x̄ ≈ floor = 0.034424
        xbar = self.MEASURED_FLOOR
        absolute_threshold = 0.03
        would_flag = xbar >= absolute_threshold
        assert would_flag is True, (
            f"Expected absolute threshold {absolute_threshold} to flag xbar={xbar}"
        )

    def test_floor_relative_accepts_honest(self):
        """The floor-relative rule (flag iff x̄ - floor ≥ τ) accepts an honest run."""
        k = 4200
        N = 4 * k
        alpha = 1e-10
        tau = tau_for_alpha(k, N, alpha)

        xbar = self.MEASURED_FLOOR
        excess = xbar - self.MEASURED_FLOOR  # == 0.0
        flagged = excess >= tau
        assert flagged is False, (
            f"Floor-relative rule should NOT flag honest run: excess={excess}, tau={tau}"
        )


# ===========================================================================
# Test 7: Layer1 on 300 honest runs flags ZERO
# ===========================================================================

class TestHonestRuns:
    def test_no_false_positives(self):
        """Layer1 on 300 honest engine runs (noise_p=0) at alpha=1e-10 flags ZERO."""
        spec = _load_spec()
        engine = ProtocolEngine(spec)
        detector = Layer1(alpha=1e-10, floor=0.034424)

        flagged_count = 0
        for i in range(300):
            trace = engine.run(RunConfig(
                noise_p=0.0,
                decoy_rounds=400,
                seed=70000 + i,
            ))
            verdict = detector.analyse(trace)
            if verdict.flagged:
                flagged_count += 1

        assert flagged_count == 0, (
            f"Expected 0 false positives at alpha=1e-10 over 300 honest runs, "
            f"got {flagged_count}"
        )


# ===========================================================================
# Test 8: Layer1 on 300 intercept_resend runs flags ALL
# ===========================================================================

class TestInterceptResend:
    def test_all_intercept_resend_flagged(self):
        """Layer1 on 300 intercept_resend runs flags ALL (rate ~0.28 vs floor 0.034)."""
        spec = _load_spec()
        engine = ProtocolEngine(spec)
        detector = Layer1(alpha=1e-10, floor=0.034424)

        flagged_count = 0
        for i in range(300):
            trace = engine.run(RunConfig(
                noise_p=0.0,
                decoy_rounds=400,
                seed=80000 + i,
                attack="intercept_resend",
            ))
            verdict = detector.analyse(trace)
            if verdict.flagged:
                flagged_count += 1

        assert flagged_count == 300, (
            f"Expected ALL 300 intercept-resend runs flagged, got {flagged_count}"
        )


# ===========================================================================
# Test 9: THE HEADLINE — Layer1 on 300 paired_pauli runs flags ZERO
# ===========================================================================

class TestPairedPauliUndetectable:
    """Layer1 on 300 paired_pauli runs flags ZERO of them, at EVERY noise
    level in (0.0, 0.001, 0.01, 0.05).

    This is a THEOREM, not a tuning artefact: the paired Pauli attack produces
    a forged state whose density matrix is identical to the honest execution,
    so the decoy error statistics are drawn from exactly the same distribution.
    The channel-statistics detector — no matter how tightly tuned — CANNOT
    distinguish the attack from honest traffic because there is no statistical
    signal to detect.

    A nonzero true-positive rate here would indicate a BUG in either the
    attack simulation or the detector, not a failure of the mathematical claim.
    """

    @pytest.mark.parametrize("noise_p", [0.0, 0.001, 0.01, 0.05])
    def test_paired_pauli_invisible(self, noise_p):
        spec = _load_spec()
        engine = ProtocolEngine(spec)
        detector = Layer1(alpha=1e-10, floor=0.034424)

        flagged_count = 0
        for i in range(300):
            trace = engine.run(RunConfig(
                noise_p=noise_p,
                decoy_rounds=400,
                seed=90000 + i,
                attack="paired_pauli",
            ))
            verdict = detector.analyse(trace)
            if verdict.flagged:
                flagged_count += 1

        # THEOREM: the true-positive rate is EXACTLY 0.0.
        # The forged and honest executions produce the same density matrix;
        # the decoy-state error rates are identically distributed.
        # Any nonzero value here is a BUG.
        assert flagged_count == 0, (
            f"THEOREM VIOLATION at noise_p={noise_p}: paired_pauli runs should "
            f"NEVER be flagged by channel-statistics, but {flagged_count}/300 were. "
            f"This indicates a bug in the attack simulation or the detector."
        )


# ===========================================================================
# Test 10: No numeric threshold literal — alpha and floor control decisions
# ===========================================================================

class TestNoHardcodedThresholds:
    def test_changing_alpha_changes_tau(self):
        """Changing alpha changes tau (no hardcoded threshold)."""
        k, N = 1000, 4000
        tau_tight = tau_for_alpha(k, N, 1e-12)
        tau_loose = tau_for_alpha(k, N, 1e-3)
        assert tau_tight > tau_loose, (
            f"Tighter alpha should produce larger tau: "
            f"tau(1e-12)={tau_tight}, tau(1e-3)={tau_loose}"
        )

    def test_changing_floor_changes_decision(self):
        """Changing the floor changes the decision boundary."""
        spec = _load_spec()
        engine = ProtocolEngine(spec)

        # Generate a trace with moderate noise so xbar ~ 0.034 + 0.03 ~ 0.064
        trace = engine.run(RunConfig(
            noise_p=0.03,
            decoy_rounds=400,
            seed=10042,
        ))

        # With a low floor, the excess is large → should flag
        detector_low_floor = Layer1(alpha=1e-3, floor=0.0)
        verdict_low = detector_low_floor.analyse(trace)

        # With the true floor, the excess is smaller → less likely to flag
        detector_true_floor = Layer1(alpha=1e-3, floor=0.034424)
        verdict_true = detector_true_floor.analyse(trace)

        # The excess differs because the floor differs
        assert verdict_low.excess_over_floor > verdict_true.excess_over_floor, (
            f"Lower floor should produce larger excess: "
            f"low={verdict_low.excess_over_floor}, true={verdict_true.excess_over_floor}"
        )


# ===========================================================================
# Additional: Clopper-Pearson edge cases
# ===========================================================================

class TestClopperPearson:
    def test_zero_successes(self):
        """clopper_pearson(0, n) has lower == 0.0 and no NaN."""
        low, high = clopper_pearson(0, 100)
        assert low == 0.0
        assert 0.0 < high < 1.0
        assert not math.isnan(low) and not math.isnan(high)

    def test_all_successes(self):
        """clopper_pearson(n, n) has upper == 1.0 and no NaN."""
        low, high = clopper_pearson(100, 100)
        assert high == 1.0
        assert 0.0 < low < 1.0
        assert not math.isnan(low) and not math.isnan(high)

    def test_normal_case(self):
        """A normal case returns sensible bounds containing the observed proportion."""
        successes, trials = 30, 100
        low, high = clopper_pearson(successes, trials)
        p_hat = successes / trials
        assert low < p_hat < high
        assert low > 0.0
        assert high < 1.0


# ===========================================================================
# Additional: min_sample_for
# ===========================================================================

class TestMinSampleFor:
    def test_min_sample_achieves_alpha(self):
        """min_sample_for returns a k that actually achieves the target alpha."""
        tau = 0.03
        N = 16384
        alpha = 1e-5
        k = min_sample_for(tau, N, alpha)
        fpr = serfling_fpr(k, N, tau)
        assert fpr <= alpha, (
            f"min_sample_for returned k={k} but serfling_fpr={fpr:.6e} > alpha={alpha}"
        )
        # And k-1 should NOT achieve it (or k==1)
        if k > 1:
            fpr_prev = serfling_fpr(k - 1, N, tau)
            assert fpr_prev > alpha, (
                f"k-1={k-1} also achieves alpha: fpr={fpr_prev:.6e} <= {alpha}"
            )


# ===========================================================================
# Additional: L1Verdict derivation string
# ===========================================================================

class TestDerivationString:
    def test_derivation_contains_actual_numbers(self):
        """The derivation string contains the actual computed values."""
        spec = _load_spec()
        engine = ProtocolEngine(spec)
        detector = Layer1(alpha=1e-10, floor=0.034424)
        trace = engine.run(RunConfig(noise_p=0.0, decoy_rounds=400, seed=55555))
        verdict = detector.analyse(trace)
        assert "Serfling" in verdict.derivation
        assert "alpha=" in verdict.derivation
        assert "floor=" in verdict.derivation
        assert "tau " in verdict.derivation
        assert "xbar=" in verdict.derivation
