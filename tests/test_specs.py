from __future__ import annotations

from pathlib import Path
import pytest

from pauliguard.engine.spec_loader import (
    SchemeSpec,
    StepSpec,
    discover_specs,
    load_spec,
    validate_spec,
)
from pauliguard.engine.trace import Action, Party, Procedure

SPECS_DIR = Path(__file__).parent.parent / "pauliguard" / "specs"


@pytest.fixture
def all_specs() -> dict[str, SchemeSpec]:
    return discover_specs(SPECS_DIR)


def test_discover_specs_finds_exactly_three(all_specs: dict[str, SchemeSpec]):
    """1. discover_specs finds exactly 3 specs and their names match the filenames."""
    assert len(all_specs) == 3

    expected_names = {"lu-2022", "li-chan-long-2009", "decoy-bb84-qds"}
    assert set(all_specs.keys()) == expected_names

    for name, spec in all_specs.items():
        assert isinstance(spec, SchemeSpec)
        assert spec.name == name
        file_stem = Path(spec.source_path).stem
        assert file_stem == name, f"Filename stem '{file_stem}' does not match spec.name '{name}'"


def test_validate_spec_returns_empty_list_for_all_three(all_specs: dict[str, SchemeSpec]):
    """2. validate_spec returns [] for all three."""
    for name, spec in all_specs.items():
        issues = validate_spec(spec)
        assert issues == [], f"Spec '{name}' failed validation with issues: {issues}"


def test_lu_2022_procedures_and_unprotected_verify_step(all_specs: dict[str, SchemeSpec]):
    """3. lu-2022 has all five procedures, and at least one step with decoy_protected False in VERIFY."""
    lu = all_specs["lu-2022"]

    # Assert all five procedures are present
    all_procedures = [
        Procedure.INIT,
        Procedure.SIGN,
        Procedure.VERIFY,
        Procedure.PROOF_OF_ORIGIN,
        Procedure.PROOF_OF_RECEIPT,
    ]
    for proc in all_procedures:
        assert lu.has_procedure(proc), f"lu-2022 is missing procedure {proc}"

    grouped = lu.procedures()
    assert set(grouped.keys()) == set(all_procedures)

    # Assert at least one step in VERIFY is decoy_protected: False (load-bearing forgery locus)
    verify_steps = grouped[Procedure.VERIFY]
    assert len(verify_steps) > 0
    unprotected_verify = [s for s in verify_steps if not s.decoy_protected]
    assert len(unprotected_verify) > 0, "VERIFY in lu-2022 must have at least one step with decoy_protected=False"

    # Also assert that transmission steps are protected
    protected_verify = [s for s in verify_steps if s.decoy_protected]
    assert len(protected_verify) > 0, "VERIFY in lu-2022 must have protected transmission steps"


def test_decoy_bb84_qds_encryption_and_higher_decoy_fraction(all_specs: dict[str, SchemeSpec]):
    """4. decoy-bb84-qds has encryption 'none' and a strictly HIGHER fraction of decoy_protected steps than lu-2022."""
    decoy = all_specs["decoy-bb84-qds"]
    lu = all_specs["lu-2022"]

    assert decoy.encryption == "none"

    frac_decoy = sum(1 for s in decoy.steps if s.decoy_protected) / len(decoy.steps)
    frac_lu = sum(1 for s in lu.steps if s.decoy_protected) / len(lu.steps)

    # Assert the actual strict inequality
    assert frac_decoy > frac_lu, f"decoy-bb84-qds decoy fraction ({frac_decoy:.3f}) must be > lu-2022 ({frac_lu:.3f})"


def test_validate_spec_corrupted_spec(tmp_path: Path):
    """5. validate_spec returns a non-empty list for a deliberately corrupted spec.

    (unknown encryption, and a step naming an undeclared register) built in the test as a temp YAML file.
    """
    corrupted_yaml = """
name: corrupted-spec
citation: "Test Corrupted Citation"
family: "teleportation-aqs"
n_message_qubits: 2
encryption: "quantum-rot13-invalid"
verifier_set:
  - "Bob"
  - "Trent"
keys:
  - name: "k_valid"
    bits: 4
    reuse_policy: "single-use"
registers:
  - name: "reg_valid"
    qubits: 2
    owner: "Alice"
steps:
  - procedure: "INIT"
    party: "Trent"
    action: "prepare"
    registers: ["undeclared_ghost_register"]
    keys_used: ["undeclared_ghost_key"]
    decoy_protected: false
    name: "bad_step"
    detail: {}
claims:
  - "unforgeability"
assumed_fields:
  - "test_field"
"""
    tmp_file = tmp_path / "corrupted-spec.yaml"
    tmp_file.write_text(corrupted_yaml, encoding="utf-8")

    corrupted_spec = load_spec(tmp_file)
    issues = validate_spec(corrupted_spec)

    assert isinstance(issues, list)
    assert len(issues) > 0

    # Assert specific reported defects
    assert any("encryption" in issue.lower() and "quantum-rot13-invalid" in issue for issue in issues)
    assert any("undeclared_ghost_register" in issue for issue in issues)
    assert any("undeclared_ghost_key" in issue for issue in issues)


def test_every_spec_has_assumed_fields(all_specs: dict[str, SchemeSpec]):
    """6. every spec has a non-empty assumed_fields list (honesty requirement)."""
    for name, spec in all_specs.items():
        assert isinstance(spec.assumed_fields, list), f"Spec '{name}' assumed_fields must be a list"
        assert len(spec.assumed_fields) > 0, f"Spec '{name}' must have a non-empty assumed_fields list"
        assert all(isinstance(f, str) and len(f.strip()) > 0 for f in spec.assumed_fields), (
            f"Spec '{name}' has blank or non-string entries in assumed_fields"
        )


def test_validate_spec_additional_edge_cases(tmp_path: Path):
    """Extra validation rules: n_message_qubits < 1, empty steps, bad party, bad reuse_policy."""
    bad_yaml = """
name: bad-edge-cases
citation: "Edge cases"
family: "teleportation-aqs"
n_message_qubits: 0
encryption: "qotp"
verifier_set:
  - "NonexistentParty"
keys:
  - name: "k_bad"
    bits: 4
    reuse_policy: "eternal"
registers: []
steps: []
claims: []
assumed_fields: ["honesty"]
"""
    tmp_file = tmp_path / "bad-edge-cases.yaml"
    tmp_file.write_text(bad_yaml, encoding="utf-8")

    spec = load_spec(tmp_file)
    issues = validate_spec(spec)

    assert any("n_message_qubits" in issue for issue in issues)
    assert any("empty steps" in issue for issue in issues)
    assert any("NonexistentParty" in issue for issue in issues)
    assert any("reuse_policy" in issue for issue in issues)
