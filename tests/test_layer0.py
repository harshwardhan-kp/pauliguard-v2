from __future__ import annotations

from pathlib import Path
import pytest

from pauliguard.detectors.layer0 import (
    Finding,
    Layer0,
    SessionLedger,
    analyse_stream,
)
from pauliguard.engine.protocol import ProtocolEngine, RunConfig
from pauliguard.engine.spec_loader import SchemeSpec, StepSpec, load_spec
from pauliguard.engine.trace import (
    Action,
    KeyDecl,
    Party,
    Procedure,
    RegisterDecl,
    Step,
    Trace,
)

SPECS_DIR = Path(__file__).parent.parent / "pauliguard" / "specs"


def test_zero_false_positives_on_honest_lu_2022():
    """1. ZERO findings of severity 'critical' on 200 honest lu-2022 runs, each with a fresh

    session_id and nonce. This is the false-positive-rate-zero-by-construction claim;
    assert it as an exact 0.
    """
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)

    total_critical = 0
    for i in range(200):
        trace = engine.run(RunConfig(seed=10000 + i, decoy_rounds=50))
        l0 = Layer0(spec)
        findings = l0.analyse(trace)
        critical = [f for f in findings if f.severity == "critical"]
        total_critical += len(critical)

    assert total_critical == 0, f"Expected 0 critical findings on 200 honest runs, got {total_critical}"


def test_replay_session_detected():
    """2. REPLAY: feed the SAME trace object twice through analyse_stream; the second analysis

    must contain L0.REPLAY_SESSION. Assert the first analysis does NOT contain it.
    """
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=42, decoy_rounds=50))

    results = analyse_stream(spec, [trace, trace])
    assert len(results) == 2
    first_analysis, second_analysis = results[0], results[1]

    # First analysis does NOT contain L0.REPLAY_SESSION
    assert not any(f.code == "L0.REPLAY_SESSION" for f in first_analysis)

    # Second analysis MUST contain L0.REPLAY_SESSION
    replay_findings = [f for f in second_analysis if f.code == "L0.REPLAY_SESSION"]
    assert len(replay_findings) == 1
    assert replay_findings[0].severity == "critical"
    assert replay_findings[0].evidence["session_id"] == trace.session_id


def test_key_reuse_detected():
    """3. KEY REUSE: two distinct runs that reuse single-use key material must yield

    L0.KEY_REUSE on the second.
    """
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace1 = engine.run(RunConfig(seed=101, decoy_rounds=50, force_key_reuse=True))
    trace2 = engine.run(RunConfig(seed=102, decoy_rounds=50, force_key_reuse=True))

    assert trace1.session_id != trace2.session_id
    assert trace1.nonce != trace2.nonce

    results = analyse_stream(spec, [trace1, trace2])
    first_analysis, second_analysis = results[0], results[1]

    assert not any(f.code == "L0.KEY_REUSE" for f in first_analysis)
    key_reuse_findings = [f for f in second_analysis if f.code == "L0.KEY_REUSE"]
    assert len(key_reuse_findings) > 0
    assert all(f.severity == "critical" for f in key_reuse_findings)


def test_unauthorized_verifier():
    """4. UNAUTHORIZED VERIFIER: take an honest trace, mutate one VERIFY step party to

    Party.EVE, and assert L0.UNAUTHORIZED_VERIFIER is reported.
    """
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=201, decoy_rounds=50))

    # Mutate one VERIFY step party to Party.EVE
    verify_step = next(s for s in trace.steps if s.procedure == Procedure.VERIFY)
    verify_step.party = Party.EVE

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    unauth_findings = [f for f in findings if f.code == "L0.UNAUTHORIZED_VERIFIER"]
    assert len(unauth_findings) > 0
    assert unauth_findings[0].severity == "critical"
    assert unauth_findings[0].step == verify_step.index


def test_step_order_violation():
    """5. STEP ORDER: mutate a step index and assert L0.STEP_ORDER."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=301, decoy_rounds=50))

    trace.steps[1].index = 99

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    order_findings = [f for f in findings if f.code == "L0.STEP_ORDER"]
    assert len(order_findings) > 0
    assert order_findings[0].severity == "critical"


def test_missing_procedure_warning():
    """6. MISSING PROCEDURE: build a spec-like object claiming non_repudiation_receipt

    but with no PROOF_OF_RECEIPT step, and assert L0.MISSING_PROCEDURE at severity 'warning'.
    """
    mock_spec = SchemeSpec(
        name="mock-spec",
        citation="Test Citation",
        family="decoy-state-qds",
        n_message_qubits=2,
        encryption="none",
        verifier_set=[Party.BOB],
        keys=[],
        registers=[],
        steps=[],
        claims=["non_repudiation_receipt"],
        assumed_fields=["test"],
        source_path="",
    )

    l0 = Layer0(mock_spec)
    trace = Trace(schema_version="1.0", scheme="mock-spec", steps=[])
    findings = l0.analyse(trace)

    missing_findings = [f for f in findings if f.code == "L0.MISSING_PROCEDURE"]
    assert len(missing_findings) == 1
    assert missing_findings[0].severity == "warning"
    assert "unsupported by the specification itself" in missing_findings[0].message


def test_malformed_trace_never_raises():
    """7. analyse() never raises on a deliberately malformed trace (empty Trace())."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    l0 = Layer0(spec)

    empty_trace = Trace()
    findings = l0.analyse(empty_trace)
    assert isinstance(findings, list)

    corrupt_trace = Trace(steps=[None], keys=[None], registers=[None])  # type: ignore
    findings_corrupt = l0.analyse(corrupt_trace)
    assert isinstance(findings_corrupt, list)


def test_decoy_bb84_qds_missing_procedure():
    """8. On the decoy-bb84-qds scheme, assert L0.MISSING_PROCEDURE is reported for

    any repudiation claim it makes without the matching procedure, OR that it makes no
    such claim. Whichever holds, the test must assert the actual consistent behaviour,
    not skip.
    """
    decoy_spec = load_spec(SPECS_DIR / "decoy-bb84-qds.yaml")
    l0 = Layer0(decoy_spec)

    has_origin_proc = decoy_spec.has_procedure(Procedure.PROOF_OF_ORIGIN)
    has_receipt_proc = decoy_spec.has_procedure(Procedure.PROOF_OF_RECEIPT)
    claims_origin = "non_repudiation_origin" in decoy_spec.claims
    claims_receipt = "non_repudiation_receipt" in decoy_spec.claims

    trace = Trace(
        schema_version="1.0",
        scheme=decoy_spec.name,
        steps=[
            Step(index=i, procedure=s.procedure, party=s.party, action=s.action)
            for i, s in enumerate(decoy_spec.steps)
        ],
    )
    findings = l0.analyse(trace)
    missing_findings = [f for f in findings if f.code == "L0.MISSING_PROCEDURE"]

    if claims_origin and not has_origin_proc:
        assert any(
            f.code == "L0.MISSING_PROCEDURE"
            and f.severity == "warning"
            and "non_repudiation_origin" in f.message
            for f in missing_findings
        )
    if claims_receipt and not has_receipt_proc:
        assert any(
            f.code == "L0.MISSING_PROCEDURE"
            and f.severity == "warning"
            and "non_repudiation_receipt" in f.message
            for f in missing_findings
        )
    if not (claims_origin and not has_origin_proc) and not (claims_receipt and not has_receipt_proc):
        assert len(missing_findings) == 0


def test_procedure_order_violation():
    """Test L0.PROCEDURE_ORDER when SIGN appears before INIT."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=401, decoy_rounds=50))

    # Swap procedure of step 0 (INIT) with step 2 (SIGN)
    trace.steps[0].procedure = Procedure.SIGN
    trace.steps[2].procedure = Procedure.INIT

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    proc_findings = [f for f in findings if f.code == "L0.PROCEDURE_ORDER"]
    assert len(proc_findings) > 0
    assert proc_findings[0].severity == "critical"


def test_spec_divergence():
    """Test L0.SPEC_DIVERGENCE when action is altered."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=501, decoy_rounds=50))

    trace.steps[0].action = Action.REJECT

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    div_findings = [f for f in findings if f.code == "L0.SPEC_DIVERGENCE"]
    assert len(div_findings) > 0
    assert div_findings[0].severity == "critical"


def test_undeclared_register_and_key():
    """Test L0.UNDECLARED_REGISTER and L0.UNDECLARED_KEY."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=601, decoy_rounds=50))

    trace.steps[0].registers.append("ghost_reg")
    trace.steps[0].keys_used.append("ghost_key")

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    assert any(f.code == "L0.UNDECLARED_REGISTER" and "ghost_reg" in f.message for f in findings)
    assert any(f.code == "L0.UNDECLARED_KEY" and "ghost_key" in f.message for f in findings)


def test_register_after_consume():
    """Test L0.REGISTER_AFTER_CONSUME."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=701, decoy_rounds=50))

    # Set consumed_step for msg to 1, then use it in step 2
    for r in trace.registers:
        if r.name == "msg":
            r.consumed_step = 1

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    consume_findings = [f for f in findings if f.code == "L0.REGISTER_AFTER_CONSUME"]
    assert len(consume_findings) > 0
    assert consume_findings[0].severity == "critical"


def test_replay_nonce_detected():
    """Test L0.REPLAY_NONCE."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace1 = engine.run(RunConfig(seed=801, decoy_rounds=50))
    trace2 = engine.run(RunConfig(seed=802, decoy_rounds=50))

    # Different session_ids, but identical nonces
    trace2.session_id = "fresh-session-123"
    trace2.nonce = trace1.nonce

    ledger = SessionLedger()
    l0 = Layer0(spec, ledger=ledger)

    f1 = l0.analyse(trace1)
    assert not any(f.code == "L0.REPLAY_NONCE" for f in f1)

    f2 = l0.analyse(trace2)
    nonce_findings = [f for f in f2 if f.code == "L0.REPLAY_NONCE"]
    assert len(nonce_findings) == 1
    assert nonce_findings[0].severity == "critical"


def test_no_false_positives_across_many_runs_sharing_one_ledger():
    """Regression test: One Layer0 with ONE SessionLedger. Run 400 honest lu-2022 runs through it.

    Assert the TOTAL number of 'critical' findings is EXACTLY 0.
    """
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    ledger = SessionLedger()
    l0 = Layer0(spec, ledger=ledger)

    total_critical = 0
    for i in range(400):
        trace = engine.run(RunConfig(seed=20000 + i, decoy_rounds=50))
        findings = l0.analyse(trace)
        critical = [f for f in findings if f.severity == "critical"]
        total_critical += len(critical)

    assert total_critical == 0, f"Expected 0 critical findings across 400 honest runs, got {total_critical}"


def test_two_runs_force_key_reuse_yields_key_reuse():
    """Two runs with force_key_reuse=True through one ledger -> second yields L0.KEY_REUSE."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    ledger = SessionLedger()
    l0 = Layer0(spec, ledger=ledger)

    trace1 = engine.run(RunConfig(seed=501, decoy_rounds=50, force_key_reuse=True))
    trace2 = engine.run(RunConfig(seed=502, decoy_rounds=50, force_key_reuse=True))

    f1 = l0.analyse(trace1)
    assert not any(f.code == "L0.KEY_REUSE" for f in f1)

    f2 = l0.analyse(trace2)
    reuse_findings = [f for f in f2 if f.code == "L0.KEY_REUSE"]
    assert len(reuse_findings) > 0
    assert all(f.severity == "critical" for f in reuse_findings)
    for f in reuse_findings:
        assert f.evidence["digest"] in f.message


def test_trace_with_key_digests_cleared_yields_no_key_binding_warning():
    """A trace with key_digests cleared yields L0.NO_KEY_BINDING at severity 'warning' and NOT L0.KEY_REUSE."""
    spec = load_spec(SPECS_DIR / "lu-2022.yaml")
    engine = ProtocolEngine(spec)
    trace = engine.run(RunConfig(seed=601, decoy_rounds=50))
    trace.key_digests = {}

    l0 = Layer0(spec)
    findings = l0.analyse(trace)

    assert not any(f.code == "L0.KEY_REUSE" for f in findings)
    warning_findings = [f for f in findings if f.code == "L0.NO_KEY_BINDING"]
    assert len(warning_findings) == 1
    assert warning_findings[0].severity == "warning"


def test_session_ledger_methods():
    """Unit tests for SessionLedger methods."""
    ledger = SessionLedger()
    assert ledger.seen_session("sess1") is False
    assert ledger.seen_nonce("nonce1") is False
    assert ledger.key_uses("k1") == 0
    assert ledger.key_material_uses("k1", "digest1") == 0

    trace = Trace(
        session_id="sess1",
        nonce="nonce1",
        keys=[KeyDecl(name="k1", bits=4, reuse_policy="single-use")],
        key_digests={"k1": "digest1"},
    )
    ledger.record(trace)

    assert ledger.seen_session("sess1") is True
    assert ledger.seen_session("sess2") is False
    assert ledger.seen_nonce("nonce1") is True
    assert ledger.seen_nonce("nonce2") is False
    assert ledger.key_uses("k1") == 1
    assert ledger.key_material_uses("k1", "digest1") == 1
    assert ledger.key_material_uses("k1", "digest2") == 0

    ledger.record(trace)
    assert ledger.key_uses("k1") == 2
    assert ledger.key_material_uses("k1", "digest1") == 2

    ledger.reset()
    assert ledger.seen_session("sess1") is False
    assert ledger.seen_nonce("nonce1") is False
    assert ledger.key_uses("k1") == 0
    assert ledger.key_material_uses("k1", "digest1") == 0
