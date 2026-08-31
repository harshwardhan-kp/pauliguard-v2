"""Tests for static dispute-resolution analysis and threat model gap reporting."""

from __future__ import annotations

from pathlib import Path
import pytest

from pauliguard.attacks.repudiation import (
    DisputeAnalyser,
    DisputeFinding,
    threat_model_gap_table,
)
from pauliguard.engine.spec_loader import SchemeSpec, discover_specs, load_spec

SPECS_DIR = Path(__file__).parent.parent / "pauliguard" / "specs"


@pytest.fixture
def all_specs() -> dict[str, SchemeSpec]:
    return discover_specs(SPECS_DIR)


def test_real_specs_analyse_never_raises(all_specs: dict[str, SchemeSpec]):
    """1. For each of the real specs, analyse() runs without raising and returns a list."""
    assert len(all_specs) >= 3
    for name, spec in all_specs.items():
        analyser = DisputeAnalyser(spec)
        findings = analyser.analyse()
        assert isinstance(findings, list), f"Expected list of findings for spec '{name}', got {type(findings)}"
        assert all(isinstance(f, DisputeFinding) for f in findings), f"All elements for '{name}' must be DisputeFinding"


def test_receipt_no_procedure_when_claimed(tmp_path: Path):
    """2. Build a spec (a temp YAML) that CLAIMS non_repudiation_receipt but has NO PROOF_OF_RECEIPT steps,

    and assert DR.RECEIPT_NO_PROCEDURE with claimed_by_scheme True and severity critical.
    """
    spec_yaml = """
name: test-no-receipt-proc
citation: "Test Citation"
family: "teleportation-aqs"
n_message_qubits: 2
encryption: "qotp"
verifier_set:
  - "Bob"
  - "Trent"
keys:
  - name: "k_AT"
    bits: 4
    reuse_policy: "single-use"
registers:
  - name: "msg"
    qubits: 2
    owner: "Alice"
steps:
  - procedure: "SIGN"
    party: "Alice"
    action: "prepare"
    registers: ["msg"]
    keys_used: []
    decoy_protected: false
claims:
  - "unforgeability"
  - "non_repudiation_receipt"
assumed_fields:
  - "test"
"""
    tmp_file = tmp_path / "test-no-receipt-proc.yaml"
    tmp_file.write_text(spec_yaml, encoding="utf-8")

    spec = load_spec(tmp_file)
    analyser = DisputeAnalyser(spec)
    findings = analyser.analyse()

    matching = [
        f for f in findings
        if f.code == "DR.RECEIPT_NO_PROCEDURE"
    ]
    assert len(matching) > 0, "Expected DR.RECEIPT_NO_PROCEDURE to be emitted"
    f = matching[0]
    assert f.claimed_by_scheme is True, "claimed_by_scheme must be True when claimed"
    assert f.severity == "critical", "severity must be critical when claimed"
    assert f.threat == "repudiation_of_receipt"


def test_receipt_unbound_and_false_allegation(tmp_path: Path):
    """3. Build a spec whose PROOF_OF_RECEIPT steps reference no message register,

    and assert BOTH DR.RECEIPT_UNBOUND and DR.FALSE_ALLEGATION are reported.
    """
    spec_yaml = """
name: test-receipt-unbound
citation: "Test Citation"
family: "teleportation-aqs"
n_message_qubits: 2
encryption: "qotp"
verifier_set:
  - "Bob"
  - "Trent"
keys:
  - name: "k_AT"
    bits: 4
    reuse_policy: "single-use"
registers:
  - name: "msg"
    qubits: 2
    owner: "Alice"
  - name: "receipt"
    qubits: 2
    owner: "Bob"
steps:
  - procedure: "SIGN"
    party: "Alice"
    action: "prepare"
    registers: ["msg"]
    keys_used: []
    decoy_protected: false
  - procedure: "PROOF_OF_RECEIPT"
    party: "Bob"
    action: "send"
    registers: ["receipt"]
    keys_used: ["k_AT"]
    decoy_protected: false
  - procedure: "PROOF_OF_RECEIPT"
    party: "Alice"
    action: "check"
    registers: ["receipt"]
    keys_used: ["k_AT"]
    decoy_protected: false
claims:
  - "unforgeability"
  - "non_repudiation_receipt"
  - "no_false_allegation"
assumed_fields:
  - "test"
"""
    tmp_file = tmp_path / "test-receipt-unbound.yaml"
    tmp_file.write_text(spec_yaml, encoding="utf-8")

    spec = load_spec(tmp_file)
    analyser = DisputeAnalyser(spec)
    findings = analyser.analyse()

    codes = [f.code for f in findings]
    assert "DR.RECEIPT_UNBOUND" in codes, "DR.RECEIPT_UNBOUND must be emitted when receipt lacks message register"
    assert "DR.FALSE_ALLEGATION" in codes, "DR.FALSE_ALLEGATION must be emitted when receipt lacks message register"

    fa_finding = next(f for f in findings if f.code == "DR.FALSE_ALLEGATION")
    assert fa_finding.threat == "false_allegation"
    assert fa_finding.severity == "critical"


def test_plaintext_before_arbitration(tmp_path: Path):
    """4. Build a spec where Bob measures the message register before Trent performs any VERIFY step,

    and assert DR.PLAINTEXT_BEFORE_ARBITRATION.
    """
    spec_yaml = """
name: test-plaintext-before-arbitration
citation: "Test Citation"
family: "teleportation-aqs"
n_message_qubits: 2
encryption: "qotp"
verifier_set:
  - "Bob"
  - "Trent"
keys:
  - name: "k_AT"
    bits: 4
    reuse_policy: "single-use"
registers:
  - name: "msg"
    qubits: 2
    owner: "Alice"
steps:
  - procedure: "SIGN"
    party: "Alice"
    action: "prepare"
    registers: ["msg"]
    keys_used: []
    decoy_protected: false
  # Step 1: Bob measures msg BEFORE Trent's verify step
  - procedure: "VERIFY"
    party: "Bob"
    action: "measure"
    registers: ["msg"]
    keys_used: []
    decoy_protected: false
  # Step 2: Trent verifies
  - procedure: "VERIFY"
    party: "Trent"
    action: "check"
    registers: ["msg"]
    keys_used: ["k_AT"]
    decoy_protected: false
claims:
  - "non_repudiation_receipt"
assumed_fields:
  - "test"
"""
    tmp_file = tmp_path / "test-plaintext-before-arbitration.yaml"
    tmp_file.write_text(spec_yaml, encoding="utf-8")

    spec = load_spec(tmp_file)
    analyser = DisputeAnalyser(spec)
    findings = analyser.analyse()

    codes = [f.code for f in findings]
    assert "DR.PLAINTEXT_BEFORE_ARBITRATION" in codes, "Expected DR.PLAINTEXT_BEFORE_ARBITRATION to be emitted"

    pba_finding = next(f for f in findings if f.code == "DR.PLAINTEXT_BEFORE_ARBITRATION")
    assert pba_finding.severity == "critical"
    assert pba_finding.threat == "repudiation_of_receipt"


def test_unclaimed_goal_not_critical_with_claimed_true(tmp_path: Path):
    """5. A scheme that does NOT claim a goal must not produce a critical finding with claimed_by_scheme True for that goal."""
    spec_yaml = """
name: test-unclaimed-silent
citation: "Test Citation"
family: "teleportation-aqs"
n_message_qubits: 2
encryption: "qotp"
verifier_set:
  - "Bob"
keys:
  - name: "k_AT"
    bits: 4
    reuse_policy: "single-use"
registers:
  - name: "msg"
    qubits: 2
    owner: "Alice"
steps:
  - procedure: "SIGN"
    party: "Alice"
    action: "prepare"
    registers: ["msg"]
    keys_used: []
    decoy_protected: false
claims:
  - "unforgeability"
assumed_fields:
  - "test"
"""
    tmp_file = tmp_path / "test-unclaimed-silent.yaml"
    tmp_file.write_text(spec_yaml, encoding="utf-8")

    spec = load_spec(tmp_file)
    analyser = DisputeAnalyser(spec)
    findings = analyser.analyse()

    for f in findings:
        if f.threat in ("repudiation_of_origin", "repudiation_of_receipt", "false_allegation"):
            assert not (f.severity == "critical" and f.claimed_by_scheme is True), (
                f"Finding {f.code} for unclaimed threat '{f.threat}' had critical severity with claimed_by_scheme=True"
            )


def test_threat_model_gap_table_structure(all_specs: dict[str, SchemeSpec]):
    """6. threat_model_gap_table returns a markdown string containing all three omitted threat names

    and the phrase "named by SIH26141".
    """
    table = threat_model_gap_table(all_specs)
    assert isinstance(table, str)

    table_lower = table.lower()
    assert "repudiation of origin" in table_lower, "Table must name repudiation of origin"
    assert "repudiation of receipt" in table_lower, "Table must name repudiation of receipt"
    assert "false allegation" in table_lower, "Table must name false allegation"
    assert "named by sih26141" in table_lower, "Table must contain column/header 'named by SIH26141'"


def test_informational_findings_for_real_schemes(all_specs: dict[str, SchemeSpec], capsys: pytest.CaptureFixture):
    """7. Report, as a non-failing informational assertion, the actual findings for lu-2022 and li-chan-long-2009."""
    for scheme_name in ["lu-2022", "li-chan-long-2009", "decoy-bb84-qds"]:
        spec = all_specs[scheme_name]
        analyser = DisputeAnalyser(spec)
        findings = analyser.analyse()
        assert isinstance(findings, list)

        print(f"\n=== Dispute Findings for {scheme_name} ===")
        for f in findings:
            print(f"  [{f.severity.upper()}] {f.code} ({f.threat}): {f.message} (claimed={f.claimed_by_scheme})")
