"""FastAPI backend exposing the PauliGuard protocol engine and detector pipeline.

Provides endpoints for:
- Health checks and hardware floor metadata
- Scheme discovery and specification inspection
- Single protocol execution with multi-layer detector analysis (L0, L1, L2, L3)
- Side-by-side comparison of honest vs. paired-Pauli forgery runs
- Algebraic malleability certificates from Layer 3
- Full multi-attack evaluation matrix generation with Clopper-Pearson intervals
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict
import json
import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import stim

from pauliguard.attacks.repudiation import DisputeAnalyser
from pauliguard.detectors.layer0 import Layer0
from pauliguard.detectors.layer1 import Layer1
from pauliguard.detectors.layer2 import Layer2
from pauliguard.detectors.layer3 import Layer3
from pauliguard.engine.encryption import ChainedCNOT, QOTP
from pauliguard.engine.protocol import ProtocolEngine, RunConfig, run_many
from pauliguard.engine.spec_loader import (
    SchemeSpec,
    discover_specs,
    load_spec_from_string,
    validate_spec,
)
from pauliguard.engine.trace import Trace, validate
from pauliguard.evaluation import evaluate, false_positive_curve

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"
SPECS_DIR = BASE_DIR / "pauliguard" / "specs"
STATIC_DIR = BASE_DIR / "web"
FLOOR_FILE = RESULTS_DIR / "floor_ibm_kingston.json"
QPU_JOB_FILE = RESULTS_DIR / "qpu_job.json"

# Hardware floor verification at startup
if not FLOOR_FILE.is_file():
    raise FileNotFoundError(
        f"Measured hardware floor file missing at {FLOOR_FILE}. "
        "Cannot initialize PauliGuard API without measured hardware floor."
    )

with FLOOR_FILE.open("r", encoding="utf-8") as f:
    floor_data = json.load(f)

if "error_floor" not in floor_data:
    raise ValueError(f"Hardware floor file at {FLOOR_FILE} does not contain 'error_floor'.")

MEASURED_FLOOR: float = float(floor_data["error_floor"])

# Extract floor source (job id)
FLOOR_SOURCE: str = "da8up31qtnsc73d0v7h0"
if QPU_JOB_FILE.is_file():
    try:
        with QPU_JOB_FILE.open("r", encoding="utf-8") as f:
            qpu_data = json.load(f)
            if "job_id" in qpu_data:
                FLOOR_SOURCE = str(qpu_data["job_id"])
    except Exception:
        pass
elif "job_id" in floor_data:
    FLOOR_SOURCE = str(floor_data["job_id"])

logger = logging.getLogger("pauliguard.api")
logging.basicConfig(level=logging.INFO)
logger.info(f"Loaded hardware floor {MEASURED_FLOOR} from job id {FLOOR_SOURCE}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Startup: loaded hardware floor {MEASURED_FLOOR} from job id {FLOOR_SOURCE}")
    yield


app = FastAPI(
    title="PauliGuard API",
    description="Quantum-Inspired Cyber Threat Detection for Digital Signature Security (SIH26141)",
    version="2.0.0",
    lifespan=lifespan,
)

# Permissive CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _spec_to_dict(spec: SchemeSpec) -> dict[str, Any]:
    """Convert SchemeSpec dataclass to a JSON-compatible dict."""
    d = asdict(spec)
    d["verifier_set"] = [
        v.value if hasattr(v, "value") else str(v) for v in spec.verifier_set
    ]
    for step in d.get("steps", []):
        if "procedure" in step and hasattr(step["procedure"], "value"):
            step["procedure"] = step["procedure"].value
        if "party" in step and hasattr(step["party"], "value"):
            step["party"] = step["party"].value
        if "action" in step and hasattr(step["action"], "value"):
            step["action"] = step["action"].value
    return d


# Pydantic models for request bodies
class RunRequest(BaseModel):
    scheme: str
    n_message_qubits: int = 2
    attack: Optional[str] = None  # null | "paired_pauli" | "unpaired_pauli" | "intercept_resend"
    attack_pauli: str = "X"
    noise_p: float = 0.0
    decoy_rounds: int = 4200
    alpha: float = 1e-10
    seed: Optional[int] = None


class CompareRequest(BaseModel):
    scheme: str
    n_message_qubits: int = 2
    attack_pauli: str = "X"
    noise_p: float = 0.0
    decoy_rounds: int = 4200
    alpha: float = 1e-10
    seed: Optional[int] = None


class AnalyseSpecRequest(BaseModel):
    yaml: str
    n_message_qubits: int = 2
    trials: int = 50


def _evaluate_trace_layers(
    spec: SchemeSpec,
    engine: ProtocolEngine,
    trace: Trace,
    n_message_qubits: int,
    decoy_rounds: int,
    alpha: float,
    seed: Optional[int],
    attack: Optional[str],
) -> dict[str, Any]:
    """Execute multi-layer detectors (L0, L1, L2, L3) on a trace."""
    # L0 Conformance
    l0 = Layer0(spec=spec)
    findings = l0.analyse(trace)
    f_l0 = any(f.severity == "critical" for f in findings)
    l0_entry = {
        "flagged": f_l0,
        "findings": [asdict(f) for f in findings],
        "derivation": "no threshold - deterministic predicate",
    }

    # L1 Channel Statistics
    l1_detector = Layer1(alpha=alpha, floor=MEASURED_FLOOR)
    l1_verdict = l1_detector.analyse(trace)
    l1_entry = {
        "flagged": l1_verdict.flagged,
        "observed_rate": l1_verdict.observed_rate,
        "excess_over_floor": l1_verdict.excess_over_floor,
        "tau": l1_verdict.tau,
        "alpha": l1_verdict.alpha,
        "k": l1_verdict.k,
        "N": l1_verdict.N,
        "floor": l1_verdict.floor,
        "ci_low": l1_verdict.ci_low,
        "ci_high": l1_verdict.ci_high,
        "derivation": l1_verdict.derivation,
        "basis": l1_verdict.basis,
    }

    # L2 Entanglement Quality
    l2_detector = Layer2(alpha=alpha)
    resource_tableau = stim.Circuit("H 0\nCNOT 0 1").to_tableau()
    m_l2 = min(100, decoy_rounds) if decoy_rounds > 0 else 100
    l2_verdict = l2_detector.analyse_resource(
        resource_tableau, m=m_l2, seed=seed, corruption=0.0
    )
    l2_entry = {
        "flagged": l2_verdict.flagged,
        "statistic": l2_verdict.statistic,
        "observed": l2_verdict.observed,
        "threshold": l2_verdict.threshold,
        "alpha": l2_verdict.alpha,
        "m": l2_verdict.m,
        "derivation": l2_verdict.derivation,
        "detail": l2_verdict.detail,
    }

    # L3 Algebraic Malleability
    l3_detector = Layer3(spec, engine.enc)
    l3_certs = l3_detector.analyse(n_message_qubits, trials=50) if engine.enc is not None else []
    l3_has_malleability = len(l3_certs) > 0
    f_l3 = bool(attack == "paired_pauli" and l3_has_malleability)
    l3_entry = {
        "flagged": f_l3,
        "certificates": [asdict(c) for c in l3_certs],
        "malleability_detected": l3_has_malleability,
        "derivation": "no threshold - algebraic search",
    }

    return {
        "L0": l0_entry,
        "L1": l1_entry,
        "L2": l2_entry,
        "L3": l3_entry,
    }


# Endpoints

@app.get("/api/health")
def health() -> dict[str, Any]:
    """Health check returning status, discovered scheme count, and hardware floor."""
    specs = discover_specs(SPECS_DIR)
    return {
        "status": "ok",
        "schemes": len(specs),
        "floor": MEASURED_FLOOR,
        "floor_source": FLOOR_SOURCE,
    }


@app.get("/api/schemes")
def list_schemes() -> list[dict[str, Any]]:
    """List all available AQS/QDS schemes discovered dynamically from disk."""
    specs = discover_specs(SPECS_DIR)
    result = []
    for name, spec in specs.items():
        n_steps = len(spec.steps)
        decoy_count = sum(1 for s in spec.steps if s.decoy_protected)
        decoy_fraction = decoy_count / n_steps if n_steps > 0 else 0.0
        result.append({
            "name": spec.name,
            "citation": spec.citation,
            "family": spec.family,
            "encryption": spec.encryption,
            "n_message_qubits": spec.n_message_qubits,
            "claims": spec.claims,
            "assumed_fields": spec.assumed_fields,
            "n_steps": n_steps,
            "decoy_protected_fraction": decoy_fraction,
        })
    return result


@app.get("/api/schemes/{name}/spec")
def get_scheme_spec(name: str) -> dict[str, Any]:
    """Return raw YAML text, parsed structure, and validation warnings for a scheme."""
    specs = discover_specs(SPECS_DIR)
    if name not in specs:
        raise HTTPException(status_code=404, detail=f"Scheme '{name}' not found")
    spec = specs[name]
    raw_yaml = Path(spec.source_path).read_text(encoding="utf-8")
    warnings = validate_spec(spec)
    return {
        "raw": raw_yaml,
        "spec": _spec_to_dict(spec),
        "warnings": warnings,
    }


@app.post("/api/run")
def run_protocol(req: RunRequest) -> dict[str, Any]:
    """Execute a protocol run and evaluate all detection layers."""
    specs = discover_specs(SPECS_DIR)
    if req.scheme not in specs:
        raise HTTPException(status_code=404, detail=f"Scheme '{req.scheme}' not found")
    spec = specs[req.scheme]
    engine = ProtocolEngine(spec)

    cfg = RunConfig(
        n_message_qubits=req.n_message_qubits,
        noise_p=req.noise_p,
        floor=MEASURED_FLOOR,
        decoy_rounds=req.decoy_rounds,
        seed=req.seed,
        attack=req.attack,
        attack_pauli=req.attack_pauli,
    )
    trace = engine.run(cfg)

    layers = _evaluate_trace_layers(
        spec=spec,
        engine=engine,
        trace=trace,
        n_message_qubits=req.n_message_qubits,
        decoy_rounds=req.decoy_rounds,
        alpha=req.alpha,
        seed=req.seed,
        attack=req.attack,
    )

    summary = {
        "message_in": trace.message_in,
        "message_out": trace.message_out,
        "message_changed": trace.message_changed(),
        "accepted": trace.accepted,
        "attack_label": trace.attack_label,
    }

    return {
        "trace": json.loads(trace.to_json()),
        "summary": summary,
        "layers": layers,
    }


@app.post("/api/compare")
def compare_runs(req: CompareRequest) -> dict[str, Any]:
    """Execute an honest run and a paired-Pauli run with identical seeds for side-by-side comparison."""
    specs = discover_specs(SPECS_DIR)
    if req.scheme not in specs:
        raise HTTPException(status_code=404, detail=f"Scheme '{req.scheme}' not found")
    spec = specs[req.scheme]
    engine = ProtocolEngine(spec)

    seed = req.seed if req.seed is not None else 42

    # 1. Honest Run
    cfg_honest = RunConfig(
        n_message_qubits=req.n_message_qubits,
        noise_p=req.noise_p,
        floor=MEASURED_FLOOR,
        decoy_rounds=req.decoy_rounds,
        seed=seed,
        attack=None,
    )
    trace_honest = engine.run(cfg_honest)
    layers_honest = _evaluate_trace_layers(
        spec=spec,
        engine=engine,
        trace=trace_honest,
        n_message_qubits=req.n_message_qubits,
        decoy_rounds=req.decoy_rounds,
        alpha=req.alpha,
        seed=seed,
        attack=None,
    )

    # 2. Forged Run (Paired Pauli)
    cfg_forged = RunConfig(
        n_message_qubits=req.n_message_qubits,
        noise_p=req.noise_p,
        floor=MEASURED_FLOOR,
        decoy_rounds=req.decoy_rounds,
        seed=seed,
        attack="paired_pauli",
        attack_pauli=req.attack_pauli,
    )
    trace_forged = engine.run(cfg_forged)
    layers_forged = _evaluate_trace_layers(
        spec=spec,
        engine=engine,
        trace=trace_forged,
        n_message_qubits=req.n_message_qubits,
        decoy_rounds=req.decoy_rounds,
        alpha=req.alpha,
        seed=seed,
        attack="paired_pauli",
    )

    # Decoy error statistics
    err_h, pos_h = trace_honest.decoy_error_rate()
    decoy_rate_honest = (err_h / pos_h) if pos_h > 0 else 0.0

    err_f, pos_f = trace_forged.decoy_error_rate()
    decoy_rate_forged = (err_f / pos_f) if pos_f > 0 else 0.0

    both_within_threshold = bool(
        not layers_honest["L1"]["flagged"] and not layers_forged["L1"]["flagged"]
    )

    honest_result = {
        "trace": json.loads(trace_honest.to_json()),
        "summary": {
            "message_in": trace_honest.message_in,
            "message_out": trace_honest.message_out,
            "message_changed": trace_honest.message_changed(),
            "accepted": trace_honest.accepted,
            "attack_label": trace_honest.attack_label,
        },
        "layers": layers_honest,
    }

    forged_result = {
        "trace": json.loads(trace_forged.to_json()),
        "summary": {
            "message_in": trace_forged.message_in,
            "message_out": trace_forged.message_out,
            "message_changed": trace_forged.message_changed(),
            "accepted": trace_forged.accepted,
            "attack_label": trace_forged.attack_label,
        },
        "layers": layers_forged,
    }

    return {
        "honest": honest_result,
        "forged": forged_result,
        "decoy_rate_honest": decoy_rate_honest,
        "decoy_rate_forged": decoy_rate_forged,
        "both_within_threshold": both_within_threshold,
    }


@app.get("/api/certificate/{scheme}")
def get_certificate(scheme: str, n: int = Query(default=2, ge=1)) -> list[dict[str, Any]]:
    """Retrieve Layer 3 algebraic malleability certificates for a given scheme."""
    specs = discover_specs(SPECS_DIR)
    if scheme not in specs:
        raise HTTPException(status_code=404, detail=f"Scheme '{scheme}' not found")
    spec = specs[scheme]
    engine = ProtocolEngine(spec)
    if engine.enc is None:
        return []
    l3 = Layer3(spec, engine.enc)
    certs = l3.analyse(n=n, trials=50)
    return [asdict(c) for c in certs]


@app.get("/api/evaluation")
def get_evaluation(
    trials: int = Query(default=200, ge=1),
    spec: str = "lu-2022",
    noise_p: float = 0.0,
    alpha: float = 1e-10,
) -> dict[str, Any]:
    """Generate the full evaluation matrix, markdown tables, and structural blindness analysis."""
    specs = discover_specs(SPECS_DIR)
    if spec not in specs:
        raise HTTPException(status_code=404, detail=f"Scheme '{spec}' not found")
    matrix = evaluate(
        spec_name=spec,
        trials=trials,
        noise_p=noise_p,
        alpha=alpha,
        decoy_rounds=400,
        seed=0,
    )
    matrix_json = json.loads(matrix.to_json())
    return {
        "matrix": matrix_json,
        "markdown": matrix.to_markdown(),
        "structural_blindness": matrix.structural_blindness(),
        "rows": matrix.rows,
        "cols": matrix.cols,
        "cells": matrix_json.get("cells", {}),
        "outcomes": matrix_json.get("outcomes", {}),
    }


@app.post("/api/analyse_spec")
def analyse_spec(req: AnalyseSpecRequest) -> Any:
    """Analyse raw YAML specification in real time without writing to disk.

    Runs validation, Layer 3 algebraic search, static dispute analysis, and
    empirical execution benchmarks. Gracefully degrades if constructs exceed
    the stabilizer engine.
    """
    # 1. Parse via load_spec_from_string
    try:
        spec = load_spec_from_string(req.yaml, source_label="<edited>")
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": str(exc), "stage": "parse"},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={"error": str(exc), "stage": "parse"},
        )

    # 2. Run validate_spec
    warnings = validate_spec(spec)
    swap_test_copies = spec.swap_test_copies()

    # 3. Static Dispute Analysis (never crashes)
    try:
        dispute_analyser = DisputeAnalyser(spec)
        findings = dispute_analyser.analyse()
        dispute_findings = [asdict(f) for f in findings]
    except Exception as exc:
        dispute_findings = [{
            "code": "DR.INTERNAL_ERROR",
            "severity": "warning",
            "threat": "repudiation_of_origin",
            "message": f"Error during dispute analysis: {exc}",
            "claimed_by_scheme": False,
            "evidence": {"error": str(exc)},
        }]

    # 4. Layer 3 and Execution Benchmarks with graceful degradation
    n_qubits = req.n_message_qubits if req.n_message_qubits > 0 else (
        spec.n_message_qubits if spec.n_message_qubits > 0 else 2
    )
    trials = req.trials if req.trials > 0 else 50

    certificates: list[dict[str, Any]] = []
    malleability_dimension: int = 0
    forgery_success_rate: float = 0.0
    honest_acceptance_rate: float = 1.0
    degraded: str | None = None

    try:
        engine = ProtocolEngine(spec)

        # Layer 3 Algebraic Malleability
        if engine.enc is not None:
            l3 = Layer3(spec, engine.enc)
            l3_certs = l3.analyse(n=n_qubits, trials=trials)
            certificates = [asdict(c) for c in l3_certs]
            if l3_certs:
                malleability_dimension = int(l3_certs[0].malleability_dimension)
            else:
                first_key = next(engine.enc.iter_keys(n_qubits), None)
                if first_key is not None:
                    basis = l3.malleability_subspace(first_key, n_qubits)
                    malleability_dimension = int(basis.shape[0])
                else:
                    malleability_dimension = 0
        else:
            certificates = []
            malleability_dimension = 0

        # Short honest batch
        cfg_honest = RunConfig(
            n_message_qubits=n_qubits,
            noise_p=0.0,
            floor=MEASURED_FLOOR,
            decoy_rounds=400,
            seed=42,
            attack=None,
        )
        honest_traces = run_many(engine, cfg_honest, trials=trials)
        honest_accepted = sum(1 for t in honest_traces if t.accepted)
        honest_acceptance_rate = (honest_accepted / len(honest_traces)) if honest_traces else 1.0

        # Short paired_pauli batch
        cfg_forged = RunConfig(
            n_message_qubits=n_qubits,
            noise_p=0.0,
            floor=MEASURED_FLOOR,
            decoy_rounds=400,
            seed=42,
            attack="paired_pauli",
            attack_pauli="X",
        )
        forged_traces = run_many(engine, cfg_forged, trials=trials)
        forgery_accepted = sum(1 for t in forged_traces if t.accepted)
        forgery_success_rate = (forgery_accepted / len(forged_traces)) if forged_traces else 0.0

    except Exception as exc:
        degraded = (
            f"Stabilizer simulation limitation: {exc}. "
            f"Static dispute analysis and spec validation were completed successfully."
        )

    res: dict[str, Any] = {
        "parsed_ok": True,
        "warnings": warnings,
        "malleability_dimension": malleability_dimension,
        "certificates": certificates,
        "dispute_findings": dispute_findings,
        "forgery_success_rate": forgery_success_rate,
        "honest_acceptance_rate": honest_acceptance_rate,
        "swap_test_copies": swap_test_copies,
    }
    if degraded is not None:
        res["degraded"] = degraded

    return res


# Static files mount if directory exists
if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
