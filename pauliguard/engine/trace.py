from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from typing import Any


class Procedure(str, Enum):
    INIT = "INIT"
    SIGN = "SIGN"
    VERIFY = "VERIFY"
    PROOF_OF_ORIGIN = "PROOF_OF_ORIGIN"
    PROOF_OF_RECEIPT = "PROOF_OF_RECEIPT"


class Party(str, Enum):
    ALICE = "Alice"
    BOB = "Bob"
    TRENT = "Trent"
    EVE = "Eve"


class Action(str, Enum):
    PREPARE = "prepare"
    APPLY = "apply"
    SEND = "send"
    MEASURE = "measure"
    CHECK = "check"
    PUBLISH = "publish"
    STORE = "store"
    ACCEPT = "accept"
    REJECT = "reject"
    ABORT = "abort"


@dataclass
class KeyDecl:
    name: str
    bits: int
    reuse_policy: str  # "single-use" | "reusable"


@dataclass
class RegisterDecl:
    name: str
    qubits: int
    owner: Party
    created_step: int
    consumed_step: int | None = None


@dataclass
class Step:
    index: int
    procedure: Procedure
    party: Party
    action: Action
    registers: list[str] = field(default_factory=list)
    keys_used: list[str] = field(default_factory=list)
    decoy_protected: bool = False
    detail: dict = field(default_factory=dict)


@dataclass
class Measurement:
    step: int
    register: str
    basis: str  # "Z" or "X"
    outcome: list[int]
    expected: list[int] | None = None
    is_decoy: bool = False

    def errors(self) -> int:
        if self.expected is None:
            return 0
        return sum(1 for o, e in zip(self.outcome, self.expected) if o != e)

    def n_positions(self) -> int:
        return len(self.outcome)


@dataclass
class Check:
    step: int
    name: str
    passed: bool
    detail: dict = field(default_factory=dict)


@dataclass
class Trace:
    schema_version: str = "1.0"
    scheme: str = ""
    n_message_qubits: int = 0
    run_id: str = ""
    session_id: str = ""  # freshness / replay identity
    nonce: str = ""  # per-run freshness value
    honest: bool = True
    attack_label: str | None = None
    verifier_set: list[Party] = field(default_factory=list)
    keys: list[KeyDecl] = field(default_factory=list)
    registers: list[RegisterDecl] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    measurements: list[Measurement] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    message_in: list[int] = field(default_factory=list)
    message_out: list[int] = field(default_factory=list)
    accepted: bool = False
    assumed_fields: list[str] = field(default_factory=list)  # spec fields we had to assume

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    @classmethod
    def from_json(cls, s: str) -> Trace:
        data = json.loads(s)
        return cls(
            schema_version=data.get("schema_version", "1.0"),
            scheme=data.get("scheme", ""),
            n_message_qubits=data.get("n_message_qubits", 0),
            run_id=data.get("run_id", ""),
            session_id=data.get("session_id", ""),
            nonce=data.get("nonce", ""),
            honest=data.get("honest", True),
            attack_label=data.get("attack_label", None),
            verifier_set=[Party(p) for p in data.get("verifier_set", [])],
            keys=[KeyDecl(**k) for k in data.get("keys", [])],
            registers=[
                RegisterDecl(
                    name=r["name"],
                    qubits=r["qubits"],
                    owner=Party(r["owner"]),
                    created_step=r["created_step"],
                    consumed_step=r.get("consumed_step"),
                )
                for r in data.get("registers", [])
            ],
            steps=[
                Step(
                    index=st["index"],
                    procedure=Procedure(st["procedure"]),
                    party=Party(st["party"]),
                    action=Action(st["action"]),
                    registers=st.get("registers", []),
                    keys_used=st.get("keys_used", []),
                    decoy_protected=st.get("decoy_protected", False),
                    detail=st.get("detail", {}),
                )
                for st in data.get("steps", [])
            ],
            measurements=[
                Measurement(
                    step=m["step"],
                    register=m["register"],
                    basis=m["basis"],
                    outcome=m["outcome"],
                    expected=m.get("expected"),
                    is_decoy=m.get("is_decoy", False),
                )
                for m in data.get("measurements", [])
            ],
            checks=[
                Check(
                    step=c["step"],
                    name=c["name"],
                    passed=c["passed"],
                    detail=c.get("detail", {}),
                )
                for c in data.get("checks", [])
            ],
            message_in=data.get("message_in", []),
            message_out=data.get("message_out", []),
            accepted=data.get("accepted", False),
            assumed_fields=data.get("assumed_fields", []),
        )

    def decoy_measurements(self) -> list[Measurement]:
        return [m for m in self.measurements if m.is_decoy]

    def decoy_error_rate(self, basis: str | None = None) -> tuple[int, int]:
        decoys = self.decoy_measurements()
        if basis is not None:
            decoys = [m for m in decoys if m.basis == basis]
        errors = sum(m.errors() for m in decoys)
        positions = sum(m.n_positions() for m in decoys)
        return (errors, positions)

    def message_changed(self) -> bool:
        return self.message_in != self.message_out


def validate(trace: Trace) -> list[str]:
    issues: list[str] = []
    try:
        # Step indices are exactly 0..len-1 in order
        step_indices = [getattr(s, "index", None) for s in getattr(trace, "steps", [])]
        expected_indices = list(range(len(step_indices)))
        if step_indices != expected_indices:
            issues.append(
                f"Step indices are not exactly 0..{len(step_indices) - 1} in order (found: {step_indices})"
            )

        # Build declared sets
        declared_registers: set[str] = set()
        consumed_map: dict[str, int | None] = {}
        for r in getattr(trace, "registers", []):
            name = getattr(r, "name", None)
            if name is not None:
                declared_registers.add(name)
                consumed_map[name] = getattr(r, "consumed_step", None)

        declared_keys: set[str] = {
            getattr(k, "name", None) for k in getattr(trace, "keys", [])
        } - {None}

        valid_step_indices: set[int] = {
            s.index
            for s in getattr(trace, "steps", [])
            if hasattr(s, "index") and isinstance(s.index, int)
        }

        # Step validation
        for s in getattr(trace, "steps", []):
            s_idx = getattr(s, "index", "?")

            # Check undeclared registers
            for reg in getattr(s, "registers", []):
                if reg not in declared_registers:
                    issues.append(f"Step {s_idx} references undeclared register '{reg}'")
                elif isinstance(s_idx, int):
                    # Check if register is used after consumed_step
                    c_step = consumed_map.get(reg)
                    if c_step is not None and s_idx > c_step:
                        issues.append(
                            f"Register '{reg}' is used at step {s_idx} after its consumed_step {c_step}"
                        )

            # Check undeclared keys
            for key in getattr(s, "keys_used", []):
                if key not in declared_keys:
                    issues.append(f"Step {s_idx} references undeclared key '{key}'")

        # Measurement validation
        for m in getattr(trace, "measurements", []):
            m_step = getattr(m, "step", None)
            if m_step not in valid_step_indices:
                issues.append(f"Measurement references nonexistent step index {m_step}")

            outcome = getattr(m, "outcome", None)
            expected = getattr(m, "expected", None)
            if expected is not None and outcome is not None:
                if len(outcome) != len(expected):
                    issues.append(
                        f"Measurement at step {m_step} has outcome length {len(outcome)} != expected length {len(expected)}"
                    )

        # Check validation
        for c in getattr(trace, "checks", []):
            c_step = getattr(c, "step", None)
            if c_step not in valid_step_indices:
                c_name = getattr(c, "name", "?")
                issues.append(f"Check '{c_name}' references nonexistent step index {c_step}")

    except Exception as exc:
        issues.append(f"Validation error: {exc}")

    return issues
