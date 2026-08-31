from __future__ import annotations

import pytest

from pauliguard.engine.trace import (
    Action,
    Check,
    KeyDecl,
    Measurement,
    Party,
    Procedure,
    RegisterDecl,
    Step,
    Trace,
    key_fingerprint,
    validate,
)


def make_valid_trace() -> Trace:
    return Trace(
        schema_version="1.0",
        scheme="GMR04",
        n_message_qubits=4,
        run_id="run-001",
        session_id="session-xyz",
        nonce="nonce-12345",
        honest=True,
        attack_label=None,
        verifier_set=[Party.BOB, Party.TRENT],
        keys=[
            KeyDecl(name="k_enc", bits=128, reuse_policy="single-use"),
            KeyDecl(name="k_auth", bits=256, reuse_policy="reusable"),
        ],
        registers=[
            RegisterDecl(
                name="msg_reg", qubits=4, owner=Party.ALICE, created_step=0, consumed_step=2
            ),
            RegisterDecl(
                name="decoy_reg", qubits=2, owner=Party.ALICE, created_step=0, consumed_step=1
            ),
            RegisterDecl(
                name="sig_reg", qubits=4, owner=Party.BOB, created_step=2, consumed_step=None
            ),
        ],
        steps=[
            Step(
                index=0,
                procedure=Procedure.INIT,
                party=Party.ALICE,
                action=Action.PREPARE,
                registers=["msg_reg", "decoy_reg"],
                keys_used=["k_enc"],
                decoy_protected=False,
                detail={"phase": "setup"},
            ),
            Step(
                index=1,
                procedure=Procedure.SIGN,
                party=Party.ALICE,
                action=Action.SEND,
                registers=["decoy_reg"],
                keys_used=[],
                decoy_protected=True,
                detail={"channel": "quantum"},
            ),
            Step(
                index=2,
                procedure=Procedure.VERIFY,
                party=Party.BOB,
                action=Action.MEASURE,
                registers=["msg_reg", "sig_reg"],
                keys_used=["k_auth"],
                decoy_protected=True,
                detail={"verifier": "Bob"},
            ),
        ],
        measurements=[
            Measurement(
                step=1,
                register="decoy_reg",
                basis="Z",
                outcome=[0, 1],
                expected=[0, 1],
                is_decoy=True,
            ),
            Measurement(
                step=2,
                register="msg_reg",
                basis="X",
                outcome=[1, 0, 1, 0],
                expected=[1, 0, 1, 0],
                is_decoy=False,
            ),
        ],
        checks=[
            Check(step=1, name="decoy_test", passed=True, detail={"tolerance": 0.05}),
            Check(step=2, name="sig_verify", passed=True, detail={}),
        ],
        message_in=[0, 1, 0, 1],
        message_out=[0, 1, 0, 1],
        accepted=True,
        assumed_fields=["field_x"],
    )


def test_trace_roundtrip_equality():
    trace = make_valid_trace()
    json_str = trace.to_json()
    reconstructed = Trace.from_json(json_str)

    # 1. Full equality of every field
    assert reconstructed == trace

    # Assert reconstructed object types for nested dataclasses
    assert isinstance(reconstructed.keys[0], KeyDecl)
    assert isinstance(reconstructed.registers[0], RegisterDecl)
    assert isinstance(reconstructed.steps[0], Step)
    assert isinstance(reconstructed.measurements[0], Measurement)
    assert isinstance(reconstructed.checks[0], Check)

    # Assert reconstructed Enum types
    assert isinstance(reconstructed.verifier_set[0], Party)
    assert isinstance(reconstructed.verifier_set[1], Party)
    assert isinstance(reconstructed.registers[0].owner, Party)
    assert isinstance(reconstructed.steps[0].procedure, Procedure)
    assert isinstance(reconstructed.steps[0].party, Party)
    assert isinstance(reconstructed.steps[0].action, Action)
    assert reconstructed.steps[0].procedure is Procedure.INIT
    assert reconstructed.steps[0].party is Party.ALICE
    assert reconstructed.steps[0].action is Action.PREPARE


def test_validate_valid_trace():
    trace = make_valid_trace()
    issues = validate(trace)
    assert issues == []


def test_validate_out_of_order_step_indices():
    trace = make_valid_trace()
    # Modify step indices to be out-of-order: 0, 2, 1
    trace.steps[1].index = 2
    trace.steps[2].index = 1

    issues = validate(trace)
    assert len(issues) > 0
    assert any("order" in issue.lower() or "step indices" in issue.lower() for issue in issues)


def test_validate_undeclared_register():
    trace = make_valid_trace()
    # Step 0 uses undeclared register "ghost_reg"
    trace.steps[0].registers.append("ghost_reg")

    issues = validate(trace)
    assert len(issues) > 0
    assert any("ghost_reg" in issue and "undeclared register" in issue.lower() for issue in issues)


def test_validate_undeclared_key():
    trace = make_valid_trace()
    # Step 0 uses undeclared key "ghost_key"
    trace.steps[0].keys_used.append("ghost_key")

    issues = validate(trace)
    assert len(issues) > 0
    assert any("ghost_key" in issue and "undeclared key" in issue.lower() for issue in issues)


def test_validate_nonexistent_step_in_measurement():
    trace = make_valid_trace()
    # Measurement references step 999 which does not exist
    trace.measurements.append(
        Measurement(
            step=999,
            register="msg_reg",
            basis="Z",
            outcome=[0, 1],
            expected=[0, 1],
            is_decoy=False,
        )
    )

    issues = validate(trace)
    assert len(issues) > 0
    assert any("999" in issue and "nonexistent step" in issue.lower() for issue in issues)


def test_validate_outcome_expected_length_mismatch():
    trace = make_valid_trace()
    # Measurement outcome length (2) != expected length (3)
    trace.measurements[0].outcome = [0, 1]
    trace.measurements[0].expected = [0, 1, 0]

    issues = validate(trace)
    assert len(issues) > 0
    assert any("length" in issue.lower() for issue in issues)


def test_validate_register_used_after_consumed():
    trace = make_valid_trace()
    # decoy_reg has consumed_step=1, let's use it at step 2
    trace.steps[2].registers.append("decoy_reg")

    issues = validate(trace)
    assert len(issues) > 0
    assert any("decoy_reg" in issue and "consumed_step" in issue.lower() for issue in issues)


def test_validate_nonexistent_step_in_check():
    trace = make_valid_trace()
    # Check references nonexistent step 77
    trace.checks.append(Check(step=77, name="invalid_step_check", passed=False))

    issues = validate(trace)
    assert len(issues) > 0
    assert any("77" in issue and "nonexistent step" in issue.lower() for issue in issues)


def test_validate_never_raises_on_malformed():
    # Pass an object with non-standard structures to verify validate never raises
    bad_trace = Trace(steps=[None])  # type: ignore[list-item]
    issues = validate(bad_trace)
    assert isinstance(issues, list)
    assert len(issues) > 0


def test_decoy_error_rate_and_filtering():
    trace = make_valid_trace()
    trace.measurements = [
        # Decoy Z: 1 error out of 4 positions
        Measurement(
            step=1,
            register="decoy_reg",
            basis="Z",
            outcome=[0, 1, 1, 0],
            expected=[0, 0, 1, 0],
            is_decoy=True,
        ),
        # Decoy Z: 2 errors out of 2 positions
        Measurement(
            step=1,
            register="decoy_reg",
            basis="Z",
            outcome=[1, 1],
            expected=[0, 0],
            is_decoy=True,
        ),
        # Decoy X: 1 error out of 4 positions
        Measurement(
            step=1,
            register="decoy_reg",
            basis="X",
            outcome=[0, 0, 0, 1],
            expected=[0, 0, 0, 0],
            is_decoy=True,
        ),
        # Non-decoy Z: 4 errors out of 4 positions (should NOT count in decoy_error_rate)
        Measurement(
            step=2,
            register="msg_reg",
            basis="Z",
            outcome=[1, 1, 1, 1],
            expected=[0, 0, 0, 0],
            is_decoy=False,
        ),
    ]

    # Test decoy_measurements helper
    decoys = trace.decoy_measurements()
    assert len(decoys) == 3
    assert all(m.is_decoy for m in decoys)

    # All decoy bases combined: (1 + 2 + 1, 4 + 2 + 4) = (4, 10)
    assert trace.decoy_error_rate() == (4, 10)

    # Filter by basis="Z": (1 + 2, 4 + 2) = (3, 6)
    assert trace.decoy_error_rate(basis="Z") == (3, 6)

    # Filter by basis="X": (1, 4) = (1, 4)
    assert trace.decoy_error_rate(basis="X") == (1, 4)

    # Filter by basis="Y": (0, 0)
    assert trace.decoy_error_rate(basis="Y") == (0, 0)


def test_measurement_errors_and_positions():
    # When expected is None, errors() is 0
    m_no_expected = Measurement(step=0, register="reg", basis="Z", outcome=[1, 0, 1], expected=None)
    assert m_no_expected.errors() == 0
    assert m_no_expected.n_positions() == 3

    # When expected is provided
    m_with_expected = Measurement(
        step=0, register="reg", basis="Z", outcome=[1, 0, 1], expected=[1, 1, 0]
    )
    assert m_with_expected.errors() == 2
    assert m_with_expected.n_positions() == 3


def test_message_changed():
    trace = make_valid_trace()

    # Same messages
    trace.message_in = [0, 1, 1, 0]
    trace.message_out = [0, 1, 1, 0]
    assert trace.message_changed() is False

    # Different messages
    trace.message_in = [0, 1, 1, 0]
    trace.message_out = [0, 1, 0, 0]
    assert trace.message_changed() is True

    # Different lengths
    trace.message_in = [0, 1]
    trace.message_out = [0, 1, 0]
    assert trace.message_changed() is True


def test_key_fingerprint_deterministic_and_distinct():
    fp1 = key_fingerprint("k_AT", ((0, 1), (1, 0)))
    fp2 = key_fingerprint("k_AT", ((0, 1), (1, 0)))
    fp3 = key_fingerprint("k_AT", ((1, 1), (1, 0)))
    fp4 = key_fingerprint("k_BT", ((0, 1), (1, 0)))

    assert fp1 == fp2
    assert fp1 != fp3
    assert fp1 != fp4
    assert len(fp1) == 16


def test_validate_key_digests():
    trace = make_valid_trace()
    trace.key_digests = {"k_enc": "1234567890abcdef"}
    assert validate(trace) == []

    # Undeclared key in key_digests
    trace.key_digests["k_ghost"] = "abcdef1234567890"
    issues = validate(trace)
    assert any("key_digests references undeclared key 'k_ghost'" in issue for issue in issues)


def test_trace_with_key_digests_roundtrip():
    trace = make_valid_trace()
    trace.key_digests = {"k_enc": "1234567890abcdef", "k_auth": "fedcba0987654321"}
    json_str = trace.to_json()
    reconstructed = Trace.from_json(json_str)
    assert reconstructed == trace
    assert reconstructed.key_digests == trace.key_digests
