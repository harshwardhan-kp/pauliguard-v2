from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

from pauliguard.engine.trace import Action, Party, Procedure

VALID_ENCRYPTIONS = {"qotp", "chained-cnot", "none"}
VALID_REUSE_POLICIES = {"single-use", "reusable"}


@dataclass
class StepSpec:
    procedure: Procedure
    party: Party
    action: Action
    registers: list[str] = field(default_factory=list)
    keys_used: list[str] = field(default_factory=list)
    decoy_protected: bool = False
    name: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class SchemeSpec:
    name: str
    citation: str
    family: str  # "teleportation-aqs" or "decoy-state-qds"
    n_message_qubits: int
    encryption: str  # "qotp" | "chained-cnot" | "none"
    verifier_set: list[Party]
    keys: list[dict]
    registers: list[dict]
    steps: list[StepSpec]
    claims: list[str]  # security goals the scheme ASSERTS
    assumed_fields: list[str]  # fields we had to assume; a deliverable
    source_path: str

    def procedures(self) -> dict[Procedure, list[StepSpec]]:
        """Group steps by procedure, preserving step order."""
        grouped: dict[Procedure, list[StepSpec]] = {}
        for step in self.steps:
            p = step.procedure
            if p not in grouped:
                grouped[p] = []
            grouped[p].append(step)
        return grouped

    def has_procedure(self, p: Procedure | str) -> bool:
        """Return True if this scheme includes any steps for procedure p."""
        if isinstance(p, str):
            try:
                p = Procedure(p)
            except (ValueError, KeyError):
                return False
        return any(step.procedure == p for step in self.steps)


def load_spec(path: str | Path) -> SchemeSpec:
    """Load a single SchemeSpec from a YAML file.

    Missing optional fields default sensibly and will never crash.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    name = str(data.get("name", ""))
    citation = str(data.get("citation", ""))
    family = str(data.get("family", ""))
    try:
        n_message_qubits = int(data.get("n_message_qubits", 0))
    except (ValueError, TypeError):
        n_message_qubits = 0
    encryption = str(data.get("encryption", "none"))

    raw_verifiers = data.get("verifier_set", [])
    verifier_set: list[Party] = []
    if isinstance(raw_verifiers, list):
        for v in raw_verifiers:
            if isinstance(v, Party):
                verifier_set.append(v)
            else:
                try:
                    verifier_set.append(Party(v))
                except (ValueError, KeyError, TypeError):
                    verifier_set.append(v)  # type: ignore[arg-type]

    keys = list(data.get("keys", [])) if isinstance(data.get("keys"), list) else []
    registers = (
        list(data.get("registers", [])) if isinstance(data.get("registers"), list) else []
    )

    raw_steps = data.get("steps", [])
    steps: list[StepSpec] = []
    if isinstance(raw_steps, list):
        for s in raw_steps:
            if isinstance(s, StepSpec):
                steps.append(s)
                continue
            if not isinstance(s, dict):
                continue

            proc_raw = s.get("procedure")
            if isinstance(proc_raw, Procedure):
                proc = proc_raw
            else:
                try:
                    proc = Procedure(proc_raw)
                except (ValueError, KeyError, TypeError):
                    proc = proc_raw  # type: ignore[assignment]

            party_raw = s.get("party")
            if isinstance(party_raw, Party):
                party = party_raw
            else:
                try:
                    party = Party(party_raw)
                except (ValueError, KeyError, TypeError):
                    party = party_raw  # type: ignore[assignment]

            act_raw = s.get("action")
            if isinstance(act_raw, Action):
                act = act_raw
            else:
                try:
                    act = Action(act_raw)
                except (ValueError, KeyError, TypeError):
                    act = act_raw  # type: ignore[assignment]

            regs_raw = s.get("registers", [])
            keys_raw = s.get("keys_used", [])
            step = StepSpec(
                procedure=proc,
                party=party,
                action=act,
                registers=list(regs_raw) if isinstance(regs_raw, list) else [],
                keys_used=list(keys_raw) if isinstance(keys_raw, list) else [],
                decoy_protected=bool(s.get("decoy_protected", False)),
                name=s.get("name"),
                detail=dict(s.get("detail", {})) if isinstance(s.get("detail"), dict) else {},
            )
            steps.append(step)

    claims = list(data.get("claims", [])) if isinstance(data.get("claims"), list) else []
    assumed_fields = (
        list(data.get("assumed_fields", []))
        if isinstance(data.get("assumed_fields"), list)
        else []
    )

    return SchemeSpec(
        name=name,
        citation=citation,
        family=family,
        n_message_qubits=n_message_qubits,
        encryption=encryption,
        verifier_set=verifier_set,
        keys=keys,
        registers=registers,
        steps=steps,
        claims=claims,
        assumed_fields=assumed_fields,
        source_path=str(p),
    )


def discover_specs(directory: str | Path) -> dict[str, SchemeSpec]:
    """Globs *.yaml in the directory and returns {name: SchemeSpec}.

    Schemes MUST be discovered from disk, never hardcoded, so that adding a scheme
    is genuinely just adding a file.
    """
    d = Path(directory)
    specs: dict[str, SchemeSpec] = {}
    for file_path in sorted(d.glob("*.yaml")):
        spec = load_spec(file_path)
        specs[spec.name] = spec
    return specs


def validate_spec(spec: SchemeSpec) -> list[str]:
    """Non-raising specification validator.

    Reports:
    - unknown encryption value
    - a step naming an undeclared register or key
    - n_message_qubits < 1
    - empty steps
    - a verifier_set party not in the Party enum
    - a key whose reuse_policy is not "single-use" or "reusable"

    Returns [] when clean.
    """
    issues: list[str] = []
    try:
        # 1. Check encryption
        enc = getattr(spec, "encryption", None)
        if enc not in VALID_ENCRYPTIONS:
            issues.append(
                f"Unknown encryption value '{enc}' (expected one of: {sorted(VALID_ENCRYPTIONS)})"
            )

        # 2. Check n_message_qubits
        n_qubits = getattr(spec, "n_message_qubits", None)
        if n_qubits is None or not isinstance(n_qubits, int) or n_qubits < 1:
            issues.append(f"n_message_qubits must be >= 1, got {n_qubits}")

        # 3. Check empty steps
        steps = getattr(spec, "steps", None)
        if not steps or len(steps) == 0:
            issues.append("Scheme has empty steps")

        # 4. Check verifier_set parties
        verifier_set = getattr(spec, "verifier_set", [])
        valid_party_values = {p.value for p in Party}
        if isinstance(verifier_set, list):
            for p in verifier_set:
                if isinstance(p, Party):
                    continue
                if isinstance(p, str) and p in valid_party_values:
                    continue
                issues.append(f"Verifier set contains party '{p}' not in Party enum")

        # 5. Check keys and reuse_policy
        declared_keys: set[str] = set()
        raw_keys = getattr(spec, "keys", [])
        if isinstance(raw_keys, list):
            for k in raw_keys:
                if isinstance(k, dict):
                    k_name = k.get("name")
                    if k_name:
                        declared_keys.add(k_name)
                    policy = k.get("reuse_policy")
                    if policy not in VALID_REUSE_POLICIES:
                        issues.append(
                            f"Key '{k_name}' has reuse_policy '{policy}' which is not 'single-use' or 'reusable'"
                        )
                elif hasattr(k, "name") and hasattr(k, "reuse_policy"):
                    declared_keys.add(k.name)
                    if k.reuse_policy not in VALID_REUSE_POLICIES:
                        issues.append(
                            f"Key '{k.name}' has reuse_policy '{k.reuse_policy}' which is not 'single-use' or 'reusable'"
                        )

        # 6. Check registers
        declared_registers: set[str] = set()
        raw_registers = getattr(spec, "registers", [])
        if isinstance(raw_registers, list):
            for r in raw_registers:
                if isinstance(r, dict):
                    r_name = r.get("name")
                    if r_name:
                        declared_registers.add(r_name)
                elif hasattr(r, "name"):
                    declared_registers.add(r.name)

        # 7. Check steps for undeclared registers and keys
        if isinstance(steps, list):
            for i, s in enumerate(steps):
                s_name = getattr(s, "name", None) or f"step {i}"
                s_regs = getattr(s, "registers", [])
                if isinstance(s_regs, list):
                    for reg in s_regs:
                        if reg not in declared_registers:
                            issues.append(
                                f"Step {i} ('{s_name}') references undeclared register '{reg}'"
                            )

                s_keys = getattr(s, "keys_used", [])
                if isinstance(s_keys, list):
                    for key in s_keys:
                        if key not in declared_keys:
                            issues.append(
                                f"Step {i} ('{s_name}') references undeclared key '{key}'"
                            )

    except Exception as exc:
        issues.append(f"Validation error: {exc}")

    return issues
