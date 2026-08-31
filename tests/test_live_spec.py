"""Tests for live spec editing, load_spec_from_string, and /api/analyse_spec.

Asserts:
1. load_spec_from_string round-trips on-disk lu-2022 YAML to an equivalent SchemeSpec
   (same name, same number of steps, same claims).
2. load_spec_from_string raises ValueError with a readable message on malformed YAML.
3. POST /api/analyse_spec with lu-2022 YAML returns parsed_ok True, malleability_dimension > 0,
   at least one certificate, and forgery_success_rate == 1.0.
4. THE FIX DIRECTION: POST lu-2022 YAML with the hardening swap_test block added (copies 8)
   and assert forgery_success_rate drops to below 0.05 while honest_acceptance_rate stays 1.0.
   Assert BOTH, since a fix that breaks honest runs is not a fix.
5. THE BREAK DIRECTION: POST lu-2022 YAML with the trent_verify_equality_predicate step REMOVED
   and assert the response still parses and returns a result (not a 500).
6. POST malformed YAML -> HTTP 400 with stage "parse", not 500.
7. POST a spec with an unknown encryption value -> parsed_ok True but a non-empty warnings list.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from pauliguard.api import app
from pauliguard.engine.spec_loader import SchemeSpec, load_spec, load_spec_from_string

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent
SPECS_DIR = ROOT_DIR / "pauliguard" / "specs"
LU_2022_PATH = SPECS_DIR / "lu-2022.yaml"


def test_1_load_spec_from_string_round_trip() -> None:
    """1. load_spec_from_string round-trips the on-disk lu-2022 YAML to an equivalent SchemeSpec

    (same name, same number of steps, same claims).
    """
    yaml_text = LU_2022_PATH.read_text(encoding="utf-8")
    spec_from_file = load_spec(LU_2022_PATH)
    spec_from_str = load_spec_from_string(yaml_text, source_label="lu-2022.yaml")

    assert isinstance(spec_from_str, SchemeSpec)
    assert spec_from_str.name == spec_from_file.name == "lu-2022"
    assert len(spec_from_str.steps) == len(spec_from_file.steps)
    assert spec_from_str.claims == spec_from_file.claims
    assert spec_from_str.encryption == spec_from_file.encryption
    assert spec_from_str.n_message_qubits == spec_from_file.n_message_qubits
    assert spec_from_str.family == spec_from_file.family
    assert spec_from_str.assumed_fields == spec_from_file.assumed_fields


def test_2_load_spec_from_string_malformed_yaml_raises_value_error() -> None:
    """2. load_spec_from_string raises ValueError with a readable message on malformed YAML."""
    malformed_yaml = "name: [broken yaml: {unclosed mapping"
    with pytest.raises(ValueError) as exc_info:
        load_spec_from_string(malformed_yaml)

    err_msg = str(exc_info.value)
    assert "Malformed YAML" in err_msg
    assert len(err_msg) > 0

    # Non-dictionary root YAML
    non_dict_yaml = "- item 1\n- item 2\n"
    with pytest.raises(ValueError) as exc_info_list:
        load_spec_from_string(non_dict_yaml)

    assert "Malformed YAML" in str(exc_info_list.value)
    assert "mapping" in str(exc_info_list.value).lower() or "dict" in str(exc_info_list.value).lower()


def test_3_analyse_spec_lu_2022_vulnerable() -> None:
    """3. POST /api/analyse_spec with the lu-2022 YAML returns parsed_ok True,

    malleability_dimension > 0, at least one certificate, and forgery_success_rate == 1.0.
    """
    yaml_text = LU_2022_PATH.read_text(encoding="utf-8")
    payload = {
        "yaml": yaml_text,
        "n_message_qubits": 2,
        "trials": 50,
    }
    response = client.post("/api/analyse_spec", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert data["parsed_ok"] is True
    assert data["malleability_dimension"] > 0
    assert len(data["certificates"]) >= 1
    assert data["forgery_success_rate"] == 1.0
    assert data["honest_acceptance_rate"] == 1.0


def test_4_the_fix_direction_swap_test_hardening() -> None:
    """4. THE FIX DIRECTION: POST the lu-2022 YAML with the hardening swap_test block added

    (copies 8) and assert forgery_success_rate drops to below 0.05 while honest_acceptance_rate
    stays 1.0. Assert BOTH, since a fix that breaks honest runs is not a fix.
    """
    yaml_text = LU_2022_PATH.read_text(encoding="utf-8")
    hardened_block = "\nhardening:\n  swap_test:\n    enabled: true\n    copies: 8\n"
    hardened_yaml = yaml_text + hardened_block

    payload = {
        "yaml": hardened_yaml,
        "n_message_qubits": 2,
        "trials": 100,
    }
    response = client.post("/api/analyse_spec", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert data["parsed_ok"] is True
    assert data["swap_test_copies"] == 8

    # Measure before/after forgery rates
    forgery_rate = data["forgery_success_rate"]
    honest_rate = data["honest_acceptance_rate"]

    assert forgery_rate < 0.05, (
        f"Hardened forgery success rate {forgery_rate:.4f} did not drop below 0.05"
    )
    assert honest_rate == 1.0, (
        f"Hardened honest acceptance rate must stay 1.0, got {honest_rate:.4f}"
    )


def test_5_the_break_direction_remove_arbitrator_check() -> None:
    """5. THE BREAK DIRECTION: POST the lu-2022 YAML with the trent_verify_equality_predicate step

    REMOVED and assert the response still parses and returns a result (not a 500).
    """
    yaml_text = LU_2022_PATH.read_text(encoding="utf-8")

    # Remove the trent_verify_equality_predicate step
    lines = yaml_text.splitlines()
    step_start = -1
    step_end = -1
    for i, line in enumerate(lines):
        if "trent_verify_equality_predicate" in line:
            # Find the start of this step (leading dash)
            for j in range(i, -1, -1):
                if lines[j].strip().startswith("- procedure:"):
                    step_start = j
                    break
            # Find the end of this step (next dash or next unindented key)
            for j in range(i + 1, len(lines)):
                if lines[j].strip().startswith("- procedure:") or (lines[j] and not lines[j].startswith(" ")):
                    step_end = j
                    break
            if step_end == -1:
                step_end = len(lines)
            break

    assert step_start != -1, "Could not find trent_verify_equality_predicate step"
    modified_lines = lines[:step_start] + lines[step_end:]
    broken_yaml = "\n".join(modified_lines)

    payload = {
        "yaml": broken_yaml,
        "n_message_qubits": 2,
        "trials": 50,
    }
    response = client.post("/api/analyse_spec", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert data["parsed_ok"] is True
    assert "forgery_success_rate" in data
    assert "honest_acceptance_rate" in data


def test_6_malformed_yaml_returns_400_with_parse_stage() -> None:
    """6. POST malformed YAML -> HTTP 400 with stage "parse", not 500."""
    malformed_yaml = "name: [unclosed mapping: {broken"
    payload = {
        "yaml": malformed_yaml,
        "n_message_qubits": 2,
        "trials": 50,
    }
    response = client.post("/api/analyse_spec", json=payload)
    assert response.status_code == 400, f"Expected HTTP 400, got {response.status_code}"

    data = response.json()
    assert data.get("stage") == "parse", f"Expected stage 'parse', got {data.get('stage')}"
    assert "error" in data, "Expected 'error' in response JSON"
    assert len(data["error"]) > 0


def test_7_unknown_encryption_warns_and_degrades() -> None:
    """7. POST a spec with an unknown encryption value -> parsed_ok True but a non-empty warnings list."""
    yaml_text = LU_2022_PATH.read_text(encoding="utf-8")
    modified_yaml = yaml_text.replace('encryption: "qotp"', 'encryption: "custom_unsupported_cipher"')

    payload = {
        "yaml": modified_yaml,
        "n_message_qubits": 2,
        "trials": 50,
    }
    response = client.post("/api/analyse_spec", json=payload)
    assert response.status_code == 200, f"Expected HTTP 200, got {response.status_code}: {response.text}"

    data = response.json()
    assert data["parsed_ok"] is True
    assert isinstance(data["warnings"], list)
    assert len(data["warnings"]) > 0, "Expected non-empty warnings list for unknown encryption"
    assert any("encryption" in w.lower() for w in data["warnings"])
    assert "degraded" in data, "Expected degraded field for unsupported stabilizer encryption"
