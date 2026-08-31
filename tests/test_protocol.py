"""Test suite for the protocol engine and validation gates.

Asserts:
1. GATE 1: Over 2000 honest runs at noise_p=0 on lu-2022, acceptance rate is EXACTLY 1.0
   and message_out == message_in every time.
2. GATE 2: Over 2000 "paired_pauli" runs at noise_p=0, the arbitrator_equality check passes
   EXACTLY 1.0 of the time AND message_changed() is True every time (for X and Y).
3. CONTROL: Over 500 "unpaired_pauli" runs, the equality check passes 0.0 of the time.
4. Every emitted trace passes validate() with an empty list, and round-trips through to_json/from_json.
5. Decoy error rate on honest runs at noise_p=0 is close to the floor (within 3 sigma of binomial),
   and is strictly HIGHER for intercept_resend.
6. Runs are reproducible: same seed gives an identical trace JSON.
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest

from pauliguard.engine.protocol import ProtocolEngine, RunConfig, run_many
from pauliguard.engine.spec_loader import discover_specs, load_spec
from pauliguard.engine.trace import Trace, validate

SPECS_DIR = Path(__file__).parent.parent / "pauliguard" / "specs"


@pytest.fixture
def specs():
    return discover_specs(SPECS_DIR)


@pytest.fixture
def lu_engine(specs):
    return ProtocolEngine(specs["lu-2022"])


def test_gate_1_honest_acceptance_lu_2022(lu_engine):
    """GATE 1: Over 2000 honest runs at noise_p=0 on lu-2022, acceptance rate is EXACTLY 1.0

    and message_out == message_in every single time.
    """
    trials = 2000
    cfg = RunConfig(n_message_qubits=2, noise_p=0.0, seed=1000, attack=None)
    traces = run_many(lu_engine, cfg, trials)

    assert len(traces) == trials

    accepted_count = sum(1 for t in traces if t.accepted)
    acceptance_rate = accepted_count / trials
    assert acceptance_rate == 1.0, f"Acceptance rate was {acceptance_rate}, expected exactly 1.0"

    # Verify message recovery
    assert all(t.message_out == t.message_in for t in traces), (
        "Teleported message output did not match input on honest runs"
    )
    assert all(not t.message_changed() for t in traces), (
        "message_changed() was True on honest run"
    )
    assert all(t.honest for t in traces)
    assert all(t.attack_label is None for t in traces)


@pytest.mark.parametrize("attack_pauli", ["X", "Y"])
def test_gate_2_paired_pauli_attack_success_rate(lu_engine, attack_pauli):
    """GATE 2: Over 2000 "paired_pauli" runs at noise_p=0, the arbitrator_equality check

    passes EXACTLY 1.0 of the time AND message_changed() is True every time.
    Assert both == 1.0 for attack_pauli in ("X", "Y").
    """
    trials = 2000
    seed_base = 2000 if attack_pauli == "X" else 5000
    cfg = RunConfig(
        n_message_qubits=2,
        noise_p=0.0,
        attack="paired_pauli",
        attack_pauli=attack_pauli,
        seed=seed_base,
    )
    traces = run_many(lu_engine, cfg, trials)

    assert len(traces) == trials

    # Check arbitrator_equality pass rate
    equality_passed_count = sum(
        1 for t in traces if any(c.name == "arbitrator_equality" and c.passed for c in t.checks)
    )
    equality_rate = equality_passed_count / trials
    assert equality_rate == 1.0, (
        f"Arbitrator equality rate was {equality_rate} for attack_pauli={attack_pauli}, expected exactly 1.0"
    )

    # Check message_changed rate
    changed_count = sum(1 for t in traces if t.message_changed())
    changed_rate = changed_count / trials
    assert changed_rate == 1.0, (
        f"Message changed rate was {changed_rate} for attack_pauli={attack_pauli}, expected exactly 1.0"
    )

    assert all(not t.honest for t in traces)
    assert all(t.attack_label == "paired_pauli" for t in traces)


def test_control_unpaired_pauli_attack_fails(lu_engine):
    """CONTROL: Over 500 "unpaired_pauli" runs the equality check passes 0.0 of the time."""
    trials = 500
    cfg = RunConfig(
        n_message_qubits=2,
        noise_p=0.0,
        attack="unpaired_pauli",
        attack_pauli="X",
        seed=8000,
    )
    traces = run_many(lu_engine, cfg, trials)

    assert len(traces) == trials

    equality_passed_count = sum(
        1 for t in traces if any(c.name == "arbitrator_equality" and c.passed for c in t.checks)
    )
    equality_rate = equality_passed_count / trials
    assert equality_rate == 0.0, (
        f"Unpaired attack equality rate was {equality_rate}, expected exactly 0.0"
    )

    # All should be rejected
    accepted_count = sum(1 for t in traces if t.accepted)
    assert accepted_count == 0, f"Unpaired attack had {accepted_count} accepted traces, expected 0"


def test_trace_validation_and_json_roundtrip(specs):
    """Every emitted trace passes validate() with an empty list, and round-trips through to_json/from_json."""
    for spec_name, spec in specs.items():
        engine = ProtocolEngine(spec)
        configs = [
            RunConfig(seed=10, attack=None),
            RunConfig(seed=20, attack="paired_pauli", attack_pauli="X"),
            RunConfig(seed=30, attack="paired_pauli", attack_pauli="Y"),
            RunConfig(seed=40, attack="unpaired_pauli", attack_pauli="X"),
            RunConfig(seed=50, attack="intercept_resend"),
        ]
        for cfg in configs:
            trace = engine.run(cfg)

            # 1. Validation returns empty list
            issues = validate(trace)
            assert issues == [], f"Trace validation failed for spec '{spec_name}', cfg={cfg}: {issues}"

            # 2. JSON roundtrip equality
            json_str = trace.to_json()
            reconstructed = Trace.from_json(json_str)
            assert reconstructed == trace, f"JSON roundtrip mismatch for spec '{spec_name}'"
            assert validate(reconstructed) == []


def test_decoy_error_rate_and_intercept_resend_elevation(lu_engine):
    """Decoy error rate on honest runs at noise_p=0 is close to the floor (within 3 sigma of binomial),

    and is strictly HIGHER for intercept_resend. Assert the inequality.
    """
    # Honest run
    cfg_honest = RunConfig(noise_p=0.0, floor=0.034423828125, decoy_rounds=4200, seed=12345)
    t_honest = lu_engine.run(cfg_honest)

    errors, total = t_honest.decoy_error_rate()
    assert total > 0
    p_floor = cfg_honest.floor
    mu = total * p_floor
    sigma = math.sqrt(total * p_floor * (1.0 - p_floor))

    # Assert within 3 sigma of binomial
    assert abs(errors - mu) <= 3 * sigma, (
        f"Honest decoy errors {errors} not within 3 sigma ({3 * sigma:.2f}) of mean {mu:.2f}"
    )

    # Intercept-resend run
    cfg_ir = RunConfig(noise_p=0.0, floor=0.034423828125, decoy_rounds=4200, attack="intercept_resend", seed=12345)
    t_ir = lu_engine.run(cfg_ir)

    ir_errors, ir_total = t_ir.decoy_error_rate()
    assert ir_total > 0

    honest_error_rate = errors / total
    ir_error_rate = ir_errors / ir_total

    # Assert strictly higher error rate for intercept-resend
    assert ir_error_rate > honest_error_rate, (
        f"Intercept-resend error rate ({ir_error_rate:.4f}) must be strictly > honest ({honest_error_rate:.4f})"
    )


def test_reproducibility_same_seed_identical_json(lu_engine):
    """Runs are reproducible: same seed gives an identical trace JSON."""
    cfg1 = RunConfig(
        n_message_qubits=2,
        noise_p=0.01,
        floor=0.034423828125,
        decoy_rounds=4200,
        seed=987654321,
        attack="paired_pauli",
        attack_pauli="X",
    )
    cfg2 = RunConfig(
        n_message_qubits=2,
        noise_p=0.01,
        floor=0.034423828125,
        decoy_rounds=4200,
        seed=987654321,
        attack="paired_pauli",
        attack_pauli="X",
    )

    trace1 = lu_engine.run(cfg1)
    trace2 = lu_engine.run(cfg2)

    assert trace1.to_json() == trace2.to_json()
    assert trace1 == trace2
