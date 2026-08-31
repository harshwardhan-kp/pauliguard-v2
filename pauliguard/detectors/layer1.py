"""Layer 1 — Channel-Statistics Detector (Decoy-QBER analysis).

Implements the SIH26141 decoy-state error-rate test using Serfling's (1974)
finite-population concentration inequality.

KEY DESIGN DECISIONS:

1. SERFLING, NOT HOEFFDING — Decoy positions are sampled WITHOUT replacement
   from the transmitted rounds.  Hoeffding assumes WITH replacement and is
   therefore the wrong inequality; Serfling's bound is strictly tighter for
   any finite population N > k and converges to Hoeffding as N → ∞.

2. FLOOR-RELATIVE threshold — The acceptance criterion is
       flag iff (x̄ − floor) ≥ τ
   where `floor` is the calibrated device QBER (e.g. ibm_kingston = 0.034424).
   An ABSOLUTE threshold (flag iff x̄ ≥ τ_abs) is wrong: the measured floor
   already exceeds a τ of 0.03, so an absolute rule would reject honest runs
   on real hardware.

3. ONE-SIDED — We reject only on an ELEVATED error rate.  An anomalously
   LOW rate is not an attack signature.

4. NO NUMERIC THRESHOLD LITERALS — Every threshold is COMPUTED at runtime
   from (α, floor, k, N) via a named inequality.  The derivation string is
   stored in the verdict for display / audit.

REFERENCE:
    Serfling, R. J. (1974). "Probability inequalities for the sum in
    sampling without replacement."  Ann. Statist. 2(1), 39–48.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from pauliguard.engine.trace import Trace, Measurement


# ---------------------------------------------------------------------------
#  Concentration inequalities
# ---------------------------------------------------------------------------

def serfling_fpr(k: int, N: int, tau: float) -> float:
    """One-sided Serfling tail bound for sampling WITHOUT replacement.

    P(x̄ − μ ≥ τ) ≤ exp(−2 k τ² / (1 − (k−1)/N))

    Parameters
    ----------
    k : int   — sample size (number of decoy positions checked)
    N : int   — population size (total transmitted rounds)
    tau : float — excess over population mean
    """
    if k <= 0 or N <= 0 or tau <= 0:
        return 1.0
    if k > N:
        raise ValueError(f"k={k} exceeds N={N}")
    correction = 1.0 - (k - 1) / N
    if correction <= 0:
        # k == N: full census, no uncertainty
        return 0.0
    exponent = -2.0 * k * tau * tau / correction
    return math.exp(exponent)


def hoeffding_fpr(k: int, tau: float) -> float:
    """One-sided Hoeffding tail bound (sampling WITH replacement, or i.i.d.).

    P(x̄ − μ ≥ τ) ≤ exp(−2 k τ²)
    """
    if k <= 0 or tau <= 0:
        return 1.0
    exponent = -2.0 * k * tau * tau
    return math.exp(exponent)


def tau_for_alpha(k: int, N: int, alpha: float) -> float:
    """Invert the one-sided Serfling bound to find τ for a given α.

    τ = √(−ln(α) · (1 − (k−1)/N) / (2k))
    """
    if alpha <= 0.0 or alpha >= 1.0:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    if k <= 0:
        raise ValueError(f"k must be positive, got {k}")
    if N < k:
        raise ValueError(f"N={N} must be >= k={k}")
    correction = 1.0 - (k - 1) / N
    return math.sqrt(-math.log(alpha) * correction / (2.0 * k))


def min_sample_for(tau: float, N: int, alpha: float) -> int:
    """Smallest sample size k that achieves the target α for a given τ and N.

    Solves  exp(−2 k τ² / (1 − (k−1)/N)) ≤ α  for k.

    The Serfling correction factor (1 − (k−1)/N) makes the bound tighter than
    Hoeffding for finite N, so the required k is SMALLER than the Hoeffding
    estimate.  We use binary search on [1, k_hoeff].
    """
    if tau <= 0:
        raise ValueError(f"tau must be positive, got {tau}")
    if alpha <= 0 or alpha >= 1:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    if N <= 0:
        raise ValueError(f"N must be positive, got {N}")

    # Hoeffding gives an UPPER bound on the required k (Serfling is tighter)
    k_upper = math.ceil(-math.log(alpha) / (2.0 * tau * tau))
    k_upper = min(max(1, k_upper), N)

    # Binary search for the smallest k in [1, k_upper] where serfling_fpr <= alpha
    lo, hi = 1, k_upper
    # First check: if even k_upper doesn't achieve alpha, return N
    if serfling_fpr(k_upper, N, tau) > alpha:
        # Scan from k_upper to N
        for k in range(k_upper, N + 1):
            if serfling_fpr(k, N, tau) <= alpha:
                return k
        return N

    # Binary search: find smallest k where serfling_fpr(k, N, tau) <= alpha
    while lo < hi:
        mid = (lo + hi) // 2
        if serfling_fpr(mid, N, tau) <= alpha:
            hi = mid
        else:
            lo = mid + 1
    return lo


def clopper_pearson(
    successes: int, trials: int, confidence: float = 0.95
) -> tuple[float, float]:
    """Exact Clopper–Pearson binomial confidence interval.

    Returns (lower, upper) bounds on the true binomial probability parameter.

    Edge cases:
        successes == 0       → lower = 0.0
        successes == trials  → upper = 1.0
    """
    if trials <= 0:
        return (0.0, 1.0)
    alpha = 1.0 - confidence

    # Use scipy.stats.beta for the quantile function (inverse incomplete beta)
    try:
        from scipy.stats import beta as beta_dist

        if successes == 0:
            lower = 0.0
        else:
            lower = float(beta_dist.ppf(alpha / 2.0, successes, trials - successes + 1))

        if successes == trials:
            upper = 1.0
        else:
            upper = float(beta_dist.ppf(1.0 - alpha / 2.0, successes + 1, trials - successes))
    except ImportError:
        # Fallback: use a simple normal approximation (should not happen since scipy is available)
        p_hat = successes / trials
        z = _normal_quantile(1.0 - alpha / 2.0)
        margin = z * math.sqrt(p_hat * (1.0 - p_hat) / trials + 1e-30)
        lower = max(0.0, p_hat - margin)
        upper = min(1.0, p_hat + margin)

    return (lower, upper)


def _normal_quantile(p: float) -> float:
    """Rational approximation to the normal quantile (Abramowitz & Stegun 26.2.23)."""
    # Only used as a fallback if scipy is unavailable.
    if p <= 0.0:
        return -math.inf
    if p >= 1.0:
        return math.inf
    if p == 0.5:
        return 0.0
    if p < 0.5:
        return -_normal_quantile(1.0 - p)
    t = math.sqrt(-2.0 * math.log(1.0 - p))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    return t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t)


# ---------------------------------------------------------------------------
#  Verdict dataclass
# ---------------------------------------------------------------------------

@dataclass
class L1Verdict:
    """Result of an L1 channel-statistics analysis on a single trace."""

    flagged: bool
    observed_rate: float
    excess_over_floor: float       # x̄ − floor, may be negative
    tau: float
    alpha: float
    k: int
    N: int
    floor: float
    ci_low: float
    ci_high: float
    derivation: str                # human-readable derivation with actual numbers
    basis: str | None = None


# ---------------------------------------------------------------------------
#  Layer 1 detector
# ---------------------------------------------------------------------------

class Layer1:
    """Channel-statistics detector using Serfling's finite-population bound.

    Parameters
    ----------
    alpha : float
        False-positive probability target (security parameter).
    floor : float
        Calibrated device QBER (honest baseline error rate).
    population_factor : int
        When the trace does not declare N, set N = population_factor * k.
    """

    def __init__(
        self, alpha: float, floor: float, population_factor: int = 4
    ) -> None:
        if alpha <= 0.0 or alpha >= 1.0:
            raise ValueError(f"alpha must be in (0, 1), got {alpha}")
        if floor < 0.0:
            raise ValueError(f"floor must be non-negative, got {floor}")
        if population_factor < 2:
            raise ValueError(f"population_factor must be >= 2, got {population_factor}")

        self.alpha = alpha
        self.floor = floor
        self.population_factor = population_factor

    def analyse(self, trace: Trace, basis: str | None = None) -> L1Verdict:
        """Analyse a single trace for elevated decoy QBER.

        Decision rule (FLOOR-RELATIVE):
            flag iff (x̄ − floor) ≥ τ

        where τ is derived from the Serfling bound at the declared α.
        """
        errors, k = trace.decoy_error_rate(basis)

        if k == 0:
            # No decoy data — cannot decide; return unflagged with NaN-free fields
            return L1Verdict(
                flagged=False,
                observed_rate=0.0,
                excess_over_floor=0.0,
                tau=math.inf,
                alpha=self.alpha,
                k=0,
                N=0,
                floor=self.floor,
                ci_low=0.0,
                ci_high=1.0,
                derivation="No decoy measurements available",
                basis=basis,
            )

        xbar = errors / k

        # Determine population size N
        # If the trace has a total-rounds attribute, use it; otherwise derive
        # from population_factor.
        N = self.population_factor * k

        # Compute τ from Serfling inversion
        tau = tau_for_alpha(k, N, self.alpha)

        # Floor-relative decision
        excess = xbar - self.floor
        flagged = excess >= tau

        # Clopper–Pearson confidence interval
        ci_low, ci_high = clopper_pearson(errors, k, 0.95)

        # Build derivation string with actual numbers
        derivation = (
            f"tau = {tau:.6g} from Serfling with k={k}, N={N}, "
            f"alpha={self.alpha:.2e}, floor={self.floor:.6g}; "
            f"flag iff (xbar-floor) >= tau; "
            f"xbar={xbar:.6g}, excess={excess:.6g}, "
            f"{'FLAGGED' if flagged else 'PASS'}"
        )

        return L1Verdict(
            flagged=flagged,
            observed_rate=xbar,
            excess_over_floor=excess,
            tau=tau,
            alpha=self.alpha,
            k=k,
            N=N,
            floor=self.floor,
            ci_low=ci_low,
            ci_high=ci_high,
            derivation=derivation,
            basis=basis,
        )

    def analyse_both_bases(self, trace: Trace) -> dict[str, L1Verdict]:
        """Analyse both Z and X bases independently."""
        return {
            "Z": self.analyse(trace, basis="Z"),
            "X": self.analyse(trace, basis="X"),
        }
