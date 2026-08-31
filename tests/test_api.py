"""Comprehensive test suite for the PauliGuard FastAPI backend (api.py).

Verifies:
1. /api/health returns 200, status ok, schemes >= 3, and measured floor matches results/floor_ibm_kingston.json.
2. /api/schemes returns >= 3 entries, each with non-empty assumed_fields.
3. POST /api/run honest on lu-2022 -> accepted True, message_changed False, and L1.flagged False.
4. POST /api/run paired-Pauli forgery -> accepted True, message_changed True, L1.flagged False,
   L2.flagged False, L3.flagged True. (THE CORE PRODUCT CLAIM).
5. POST /api/run intercept-resend attack -> L1.flagged True.
6. POST /api/compare -> both runs present, both_within_threshold is True.
7. GET /api/certificate/lu-2022 -> at least one certificate with success_prob 1.0 and confirmed True.
8. GET /api/certificate/decoy-bb84-qds -> empty list (the contrast case).
9. Every layer entry in /api/run contains a non-empty derivation string.
10. Invalid scheme name returns 404, not 500 across endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from pauliguard.api import app, MEASURED_FLOOR, FLOOR_SOURCE

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent
FLOOR_JSON_PATH = ROOT_DIR / "results" / "floor_ibm_kingston.json"


def test_1_health_endpoint():
    """1. /api/health returns 200, status ok, schemes >= 3, and the floor equals the value in

    results/floor_ibm_kingston.json exactly.
    """
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["schemes"] >= 3

    # Verify floor matches floor_ibm_kingston.json exactly
    with FLOOR_JSON_PATH.open("r", encoding="utf-8") as f:
        expected_floor = json.load(f)["error_floor"]
    assert data["floor"] == expected_floor
    assert data["floor"] == 0.034423828125
    assert data["floor_source"] == "da8up31qtnsc73d0v7h0"


def test_2_schemes_endpoint():
    """2. /api/schemes returns >= 3 entries, each with non-empty assumed_fields."""
    response = client.get("/api/schemes")
    assert response.status_code == 200
    schemes = response.json()
    assert len(schemes) >= 3

    scheme_names = {s["name"] for s in schemes}
    assert "lu-2022" in scheme_names
    assert "li-chan-long-2009" in scheme_names
    assert "decoy-bb84-qds" in scheme_names

    for s in schemes:
        assert "name" in s
        assert "citation" in s
        assert "family" in s
        assert "encryption" in s
        assert "n_message_qubits" in s
        assert "claims" in s
        assert "assumed_fields" in s
        assert len(s["assumed_fields"]) > 0, f"Scheme {s['name']} has empty assumed_fields"
        assert "n_steps" in s
        assert s["n_steps"] > 0
        assert "decoy_protected_fraction" in s
        assert 0.0 <= s["decoy_protected_fraction"] <= 1.0


def test_3_run_honest():
    """3. POST /api/run honest on lu-2022 -> accepted True, message_changed False, and L1.flagged False."""
    payload = {
        "scheme": "lu-2022",
        "n_message_qubits": 2,
        "attack": None,
        "noise_p": 0.0,
        "decoy_rounds": 4200,
        "alpha": 1e-10,
        "seed": 42,
    }
    response = client.post("/api/run", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Protocol accepted without modification
    assert data["summary"]["accepted"] is True
    assert data["summary"]["message_changed"] is False
    assert data["summary"]["message_in"] == data["summary"]["message_out"]

    # Detector layer checks
    assert data["layers"]["L0"]["flagged"] is False
    assert data["layers"]["L1"]["flagged"] is False
    assert data["layers"]["L2"]["flagged"] is False
    assert data["layers"]["L3"]["flagged"] is False


def test_4_headline_paired_pauli_forgery_product_claim():
    """4. POST /api/run with attack 'paired_pauli' and attack_pauli 'X' -> accepted True,

    message_changed TRUE, L1.flagged FALSE, L2.flagged FALSE, L3.flagged TRUE.

    CRITICAL NOTE: This single assertion is the entire core product claim of PauliGuard.
    Under QOTP encryption, a paired Pauli forgery bypasses the protocol verification
    predicate (accepted=True) and alters the decrypted message (message_changed=True).
    Because decoy states and Bell pair resources are untouched, statistical channel detectors
    (L1) and entanglement detectors (L2) are structurally blind (flagged=False).
    Only PauliGuard's algebraic Layer 3 detects the vulnerability over GF(2) (L3.flagged=True).
    """
    payload = {
        "scheme": "lu-2022",
        "n_message_qubits": 2,
        "attack": "paired_pauli",
        "attack_pauli": "X",
        "noise_p": 0.0,
        "decoy_rounds": 4200,
        "alpha": 1e-10,
        "seed": 42,
    }
    response = client.post("/api/run", json=payload)
    assert response.status_code == 200
    data = response.json()

    # The attack succeeds at forging the signature and changing the message
    assert data["summary"]["accepted"] is True
    assert data["summary"]["message_changed"] is True
    assert data["summary"]["attack_label"] == "paired_pauli"

    # L1 and L2 are structurally blind: decoy and entanglement tests pass
    assert data["layers"]["L1"]["flagged"] is False
    assert data["layers"]["L2"]["flagged"] is False

    # L0 conformance passes (trace schema is valid)
    assert data["layers"]["L0"]["flagged"] is False

    # L3 algebraic malleability catches the forgery witness
    assert data["layers"]["L3"]["flagged"] is True
    assert len(data["layers"]["L3"]["certificates"]) > 0


def test_5_run_intercept_resend():
    """5. POST /api/run with attack 'intercept_resend' -> L1.flagged TRUE."""
    payload = {
        "scheme": "lu-2022",
        "n_message_qubits": 2,
        "attack": "intercept_resend",
        "noise_p": 0.0,
        "decoy_rounds": 4200,
        "alpha": 1e-10,
        "seed": 42,
    }
    response = client.post("/api/run", json=payload)
    assert response.status_code == 200
    data = response.json()

    # Decoy statistics detect ~25% elevated QBER
    assert data["layers"]["L1"]["flagged"] is True
    assert data["layers"]["L1"]["observed_rate"] > data["layers"]["L1"]["floor"]


def test_6_compare_endpoint():
    """6. POST /api/compare -> both runs present, and both_within_threshold is True

    (the decoy rates are statistically indistinguishable).
    """
    payload = {
        "scheme": "lu-2022",
        "n_message_qubits": 2,
        "attack_pauli": "X",
        "noise_p": 0.0,
        "decoy_rounds": 4200,
        "alpha": 1e-10,
        "seed": 42,
    }
    response = client.post("/api/compare", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "honest" in data
    assert "forged" in data
    assert "decoy_rate_honest" in data
    assert "decoy_rate_forged" in data
    assert "both_within_threshold" in data

    # Both honest and forged decoy rates are near baseline floor and within threshold
    assert data["both_within_threshold"] is True
    assert data["honest"]["summary"]["message_changed"] is False
    assert data["forged"]["summary"]["message_changed"] is True
    assert data["forged"]["layers"]["L3"]["flagged"] is True


def test_7_certificate_lu_2022():
    """7. GET /api/certificate/lu-2022 -> at least one certificate with success_probability 1.0

    and confirmed_by_execution True.
    """
    response = client.get("/api/certificate/lu-2022?n=2")
    assert response.status_code == 200
    certs = response.json()
    assert len(certs) >= 1

    valid_cert = any(
        c["success_probability"] == 1.0 and c["confirmed_by_execution"] is True
        for c in certs
    )
    assert valid_cert, f"Expected at least one confirmed cert with prob 1.0 in {certs}"


def test_8_certificate_decoy_bb84_qds():
    """8. GET /api/certificate/decoy-bb84-qds -> empty list (the contrast)."""
    response = client.get("/api/certificate/decoy-bb84-qds?n=2")
    assert response.status_code == 200
    certs = response.json()
    assert certs == []


def test_9_derivation_strings_non_empty():
    """9. Every layer entry in a /api/run response contains a non-empty 'derivation' string."""
    payload = {
        "scheme": "lu-2022",
        "n_message_qubits": 2,
        "attack": "paired_pauli",
        "attack_pauli": "X",
        "noise_p": 0.0,
        "decoy_rounds": 4200,
        "alpha": 1e-10,
        "seed": 42,
    }
    response = client.post("/api/run", json=payload)
    assert response.status_code == 200
    layers = response.json()["layers"]

    for layer_name in ("L0", "L1", "L2", "L3"):
        assert layer_name in layers
        derivation = layers[layer_name].get("derivation")
        assert isinstance(derivation, str)
        assert len(derivation.strip()) > 0, f"{layer_name} derivation is empty"

    # Verify real substituted numbers in statistical layers
    assert "Serfling" in layers["L1"]["derivation"]
    assert "tau =" in layers["L1"]["derivation"]
    assert "Azuma-Hoeffding" in layers["L2"]["derivation"]
    assert layers["L0"]["derivation"] == "no threshold - deterministic predicate"
    assert layers["L3"]["derivation"] == "no threshold - algebraic search"


def test_10_invalid_scheme_returns_404():
    """10. An invalid scheme name returns 404, not a 500."""
    # GET spec
    res_spec = client.get("/api/schemes/nonexistent-scheme-xyz/spec")
    assert res_spec.status_code == 404

    # POST run
    res_run = client.post(
        "/api/run",
        json={"scheme": "nonexistent-scheme-xyz", "n_message_qubits": 2},
    )
    assert res_run.status_code == 404

    # POST compare
    res_comp = client.post(
        "/api/compare",
        json={"scheme": "nonexistent-scheme-xyz", "n_message_qubits": 2},
    )
    assert res_comp.status_code == 404

    # GET certificate
    res_cert = client.get("/api/certificate/nonexistent-scheme-xyz")
    assert res_cert.status_code == 404

    # GET evaluation
    res_eval = client.get("/api/evaluation?spec=nonexistent-scheme-xyz")
    assert res_eval.status_code == 404


def test_scheme_spec_endpoint():
    """Verify /api/schemes/{name}/spec returns raw YAML, parsed structure, and warnings."""
    response = client.get("/api/schemes/lu-2022/spec")
    assert response.status_code == 200
    data = response.json()
    assert "raw" in data
    assert "spec" in data
    assert "warnings" in data
    assert data["spec"]["name"] == "lu-2022"
    assert isinstance(data["warnings"], list)


def test_evaluation_endpoint():
    """Verify /api/evaluation endpoint returns evaluation matrix, markdown, and blindness analysis."""
    response = client.get("/api/evaluation?trials=20&spec=lu-2022")
    assert response.status_code == 200
    data = response.json()
    assert "matrix" in data
    assert "markdown" in data
    assert "structural_blindness" in data
    assert isinstance(data["structural_blindness"], list)
    assert len(data["structural_blindness"]) > 0
    assert "STRUCTURAL BLINDNESS" in data["structural_blindness"][0]
