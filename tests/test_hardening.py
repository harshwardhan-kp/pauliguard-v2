"""Tests for SWAP-test verification hardening (THE FIX DEMO).

PROVEN:
- An honest signature is NEVER falsely rejected under SWAP-test verification
  (acceptance rate identically 1.0, one-sided error).
- Under the paired-Pauli forgery attack (U = X), the forgery success rate on lu-2022
  is 1.0 (100%), but collapses on lu-2022-hardened to (1 - 0.5)^8 = 2^-8 = 0.00390625
  (> 100x reduction), matching the analytic bound within 3 standard errors.
- Across a sweep of copies k in (1, 2, 4, 8), the measured forgery success rate matches
  2^-k within 3 standard errors and is strictly monotonically decreasing in k.
- Under a Z attack on computational-basis messages, <psi|Z|psi> = 1 so the SWAP test has
  no power (p_detect = 0), and the attack passes. This is CORRECT: Z introduces only a phase
  and does not flip bits in the computational basis, so there is no state forgery to detect.
- The hardened specification assumed_fields explicitly distinguishes the proposed fix from
  the published protocol.
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
import pytest

from pauliguard.engine.protocol import ProtocolEngine, RunConfig, run_many
from pauliguard.engine.spec_loader import SchemeSpec, discover_specs, load_spec, validate_spec

SPECS_DIR = Path(__file__).parent.parent / "pauliguard" / "specs"


@pytest.fixture
def all_specs() -> dict[str, SchemeSpec]:
    return discover_specs(SPECS_DIR)


def test_discover_specs_finds_hardened_and_validates(all_specs: dict[str, SchemeSpec]) -> None:
    """1. discover_specs finds lu-2022-hardened and validate_spec returns [] for it."""
    assert "lu-2022-hardened" in all_specs, f"lu-2022-hardened not found in {list(all_specs.keys())}"
    spec = all_specs["lu-2022-hardened"]
    assert isinstance(spec, SchemeSpec)
    assert spec.name == "lu-2022-hardened"
    assert spec.swap_test_copies() == 8

    issues = validate_spec(spec)
    assert issues == [], f"Validation of lu-2022-hardened failed with issues: {issues}"


def test_honest_runs_hardened_exact_acceptance(all_specs: dict[str, SchemeSpec]) -> None:
    """2. HONEST runs on lu-2022-hardened: acceptance rate EXACTLY 1.0 over 500 runs,

    and the swap_test_equality check passes every time. One-sided error, asserted exactly.
    """
    spec = all_specs["lu-2022-hardened"]
    engine = ProtocolEngine(spec)
    trials = 500
    cfg = RunConfig(n_message_qubits=2, noise_p=0.0, seed=42, attack=None)
    traces = run_many(engine, cfg, trials)

    assert len(traces) == trials

    accepted_count = sum(1 for t in traces if t.accepted)
    acceptance_rate = accepted_count / trials
    assert acceptance_rate == 1.0, f"Expected honest acceptance rate == 1.0, got {acceptance_rate}"

    for t in traces:
        assert t.accepted is True
        assert t.message_in == t.message_out
        swap_checks = [c for c in t.checks if c.name == "swap_test_equality"]
        assert len(swap_checks) == 1, f"Expected 1 swap_test_equality check, got {len(swap_checks)}"
        assert swap_checks[0].passed is True, "swap_test_equality check failed on honest run"


def test_the_fix_result_paired_pauli_x_forgery_collapses(all_specs: dict[str, SchemeSpec]) -> None:
    """3. THE FIX RESULT: over 2000 paired_pauli X runs, compare the forgery success rate on

    lu-2022 (must be exactly 1.0) against lu-2022-hardened (must be close to (1-0.5)^8 = 0.00390625).
    Assert the hardened rate is within 3 standard errors of 2**-8, and assert it is at least
    100x SMALLER than the unhardened rate. Put both numbers in the assertion message.
    """
    trials = 2000

    # Unhardened baseline: lu-2022
    unhardened_spec = all_specs["lu-2022"]
    unhardened_engine = ProtocolEngine(unhardened_spec)
    cfg_unhardened = RunConfig(
        n_message_qubits=2, noise_p=0.0, seed=1000, attack="paired_pauli", attack_pauli="X"
    )
    unhardened_traces = run_many(unhardened_engine, cfg_unhardened, trials)
    unhardened_forgery_count = sum(1 for t in unhardened_traces if t.accepted)
    unhardened_rate = unhardened_forgery_count / trials
    assert unhardened_rate == 1.0, (
        f"Expected unhardened lu-2022 paired_pauli X forgery rate to be 1.0, got {unhardened_rate}"
    )

    # Hardened fix: lu-2022-hardened
    hardened_spec = all_specs["lu-2022-hardened"]
    hardened_engine = ProtocolEngine(hardened_spec)
    cfg_hardened = RunConfig(
        n_message_qubits=2, noise_p=0.0, seed=1000, attack="paired_pauli", attack_pauli="X"
    )
    hardened_traces = run_many(hardened_engine, cfg_hardened, trials)
    hardened_forgery_count = sum(1 for t in hardened_traces if t.accepted)
    hardened_rate = hardened_forgery_count / trials

    p_expected = 2.0 ** (-8)  # (1 - 0.5)^8 = 0.00390625
    se = np.sqrt(p_expected * (1.0 - p_expected) / trials)
    tol = 3.0 * se
    diff = abs(hardened_rate - p_expected)

    assert diff <= tol, (
        f"Hardened forgery rate {hardened_rate:.6f} not within 3 SE ({tol:.6f}) of expected {p_expected:.6f} "
        f"(unhardened rate: {unhardened_rate:.6f}, hardened rate: {hardened_rate:.6f}, diff: {diff:.6f})"
    )

    # Assert at least 100x smaller than unhardened rate
    assert hardened_rate <= (unhardened_rate / 100.0), (
        f"Hardened forgery rate ({hardened_rate:.6f}) is not at least 100x smaller than "
        f"unhardened rate ({unhardened_rate:.6f}). Ratio = {unhardened_rate / max(hardened_rate, 1e-9):.1f}x"
    )


def test_sweep_over_copies_k(all_specs: dict[str, SchemeSpec], tmp_path: Path) -> None:
    """4. A sweep over copies k in (1,2,4,8): build the hardened spec in a temp dir with each k

    and assert the measured forgery success rate matches 2**-k within 3 standard errors, and that
    it is monotonically DECREASING in k.
    """
    hardened_source = Path(all_specs["lu-2022-hardened"].source_path).read_text(encoding="utf-8")
    k_values = (1, 2, 4, 8)
    trials = 2000
    measured_rates: list[float] = []

    for k in k_values:
        # Build spec YAML with copies: k
        k_yaml = hardened_source.replace("copies: 8", f"copies: {k}")
        k_path = tmp_path / f"lu-2022-k{k}.yaml"
        k_path.write_text(k_yaml, encoding="utf-8")

        spec_k = load_spec(k_path)
        assert spec_k.swap_test_copies() == k, f"Expected swap_test_copies == {k}, got {spec_k.swap_test_copies()}"
        issues = validate_spec(spec_k)
        assert issues == [], f"Validation failed for k={k}: {issues}"

        engine_k = ProtocolEngine(spec_k)
        cfg = RunConfig(
            n_message_qubits=2, noise_p=0.0, seed=5000 + k * 100, attack="paired_pauli", attack_pauli="X"
        )
        traces = run_many(engine_k, cfg, trials)
        forgery_count = sum(1 for t in traces if t.accepted)
        rate = forgery_count / trials
        measured_rates.append(rate)

        p_expected = 2.0 ** (-k)
        se = np.sqrt(p_expected * (1.0 - p_expected) / trials)
        tol = 3.0 * se
        diff = abs(rate - p_expected)

        assert diff <= tol, (
            f"Sweep k={k}: measured rate {rate:.6f} not within 3 SE ({tol:.6f}) of expected 2^-{k}={p_expected:.6f} "
            f"(diff={diff:.6f}, trials={trials})"
        )

    # Assert strictly monotonically decreasing in k
    for i in range(len(measured_rates) - 1):
        k_curr = k_values[i]
        k_next = k_values[i + 1]
        rate_curr = measured_rates[i]
        rate_next = measured_rates[i + 1]
        assert rate_curr > rate_next, (
            f"Forgery success rate must be monotonically decreasing in k, but for k={k_curr} "
            f"rate={rate_curr:.6f} <= for k={k_next} rate={rate_next:.6f} (all rates: {measured_rates})"
        )


def test_z_attack_passes_on_hardened_scheme(all_specs: dict[str, SchemeSpec]) -> None:
    """5. Z attack on the hardened scheme: because <psi|Z|psi> = 1 on a computational-basis message,

    the SWAP test has no power and the Z attack still passes. Assert this and add a comment
    that it is CORRECT - Z does not change the computational-basis message, so there is no
    forgery to catch. Do not hide this.
    """
    spec = all_specs["lu-2022-hardened"]
    engine = ProtocolEngine(spec)
    trials = 200
    cfg = RunConfig(
        n_message_qubits=2, noise_p=0.0, seed=42, attack="paired_pauli", attack_pauli="Z"
    )
    traces = run_many(engine, cfg, trials)

    assert len(traces) == trials
    accepted_count = sum(1 for t in traces if t.accepted)
    acceptance_rate = accepted_count / trials

    # CORRECT BEHAVIOR:
    # A Pauli Z operator acting on computational-basis states (|0>, |1>) only multiplies by
    # a phase factor (+1 or -1) without flipping the bit: Z|0> = |0>, Z|1> = -|1>.
    # Therefore, |<psi|Z|psi>| = 1.0 identically, and the SWAP test detection probability is
    # p_detect = (1 - |<psi|Z|psi>|^2)/2 = 0.0. The SWAP test has no power against Z on
    # computational-basis messages because the state is not actually altered in a detectable way;
    # there is no bit-flip forgery to catch.
    assert acceptance_rate == 1.0, (
        f"Expected Z attack acceptance rate == 1.0 (SWAP test has no power on computational basis), got {acceptance_rate}"
    )


def test_hardened_spec_assumed_fields_proposed_fix_notice(all_specs: dict[str, SchemeSpec]) -> None:
    """6. The hardened spec assumed_fields must mention that it is a proposed fix and not the

    published protocol. Assert the string is present.
    """
    spec = all_specs["lu-2022-hardened"]
    assert isinstance(spec.assumed_fields, list)
    assert len(spec.assumed_fields) > 0

    found_notice = any(
        "proposed fix" in field.lower() and "published protocol" in field.lower()
        for field in spec.assumed_fields
    )
    assert found_notice, (
        f"lu-2022-hardened assumed_fields must contain explicit notice that it is OUR PROPOSED FIX "
        f"and not the published protocol. Got: {spec.assumed_fields}"
    )
