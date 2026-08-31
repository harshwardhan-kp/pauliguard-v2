"""L0 CONFORMANCE Detector.

DESIGN PRINCIPLE:
L0 is a DETERMINISTIC PREDICATE. It has NO thresholds, NO statistics, and NO
tuning parameters of any kind. Its false-positive rate is ZERO BY CONSTRUCTION on
spec-conformant runs. It is the layer that kills replay and unauthorized
verification outright — both of which the SIH26141 problem statement names as
objectives, and neither of which is a statistical problem. Pretending replay is
statistical would be dishonest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pauliguard.engine.spec_loader import SchemeSpec, StepSpec
from pauliguard.engine.trace import Action, KeyDecl, Party, Procedure, RegisterDecl, Step, Trace


@dataclass
class Finding:
    code: str            # stable machine code, e.g. "L0.REPLAY_SESSION"
    severity: str        # "critical" | "warning"
    message: str         # human readable, names the specific register/key/step
    step: int | None = None
    evidence: dict = field(default_factory=dict)


class SessionLedger:
    """Cross-run memory. Replay is only detectable with state across runs."""

    def __init__(self) -> None:
        self._sessions: set[str] = set()
        self._nonces: set[str] = set()
        self._key_uses: dict[str, int] = {}
        self._key_material_uses: dict[tuple[str, str], int] = {}

    def record(self, trace: Trace) -> None:
        """Remember session_id, nonce, and each single-use key and (key_name, digest) pair."""
        if trace is None:
            return

        session_id = getattr(trace, "session_id", None)
        if session_id:
            self._sessions.add(str(session_id))

        nonce = getattr(trace, "nonce", None)
        if nonce:
            self._nonces.add(str(nonce))

        keys = getattr(trace, "keys", [])
        if isinstance(keys, list):
            for k in keys:
                k_name = (
                    getattr(k, "name", None)
                    if hasattr(k, "name")
                    else (k.get("name") if isinstance(k, dict) else None)
                )
                k_policy = (
                    getattr(k, "reuse_policy", None)
                    if hasattr(k, "reuse_policy")
                    else (k.get("reuse_policy") if isinstance(k, dict) else None)
                )
                if k_name and k_policy == "single-use":
                    self._key_uses[str(k_name)] = self._key_uses.get(str(k_name), 0) + 1

        key_digests = getattr(trace, "key_digests", {})
        if isinstance(key_digests, dict):
            for name, digest in key_digests.items():
                if name and digest:
                    pair = (str(name), str(digest))
                    self._key_material_uses[pair] = self._key_material_uses.get(pair, 0) + 1

    def seen_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        return str(session_id) in self._sessions

    def seen_nonce(self, nonce: str) -> bool:
        if not nonce:
            return False
        return str(nonce) in self._nonces

    def key_uses(self, key_name: str) -> int:
        if not key_name:
            return 0
        return self._key_uses.get(str(key_name), 0)

    def key_material_uses(self, name: str, digest: str) -> int:
        if not name or not digest:
            return 0
        return self._key_material_uses.get((str(name), str(digest)), 0)

    def reset(self) -> None:
        self._sessions.clear()
        self._nonces.clear()
        self._key_uses.clear()
        self._key_material_uses.clear()


class Layer0:
    def __init__(self, spec: SchemeSpec | None = None, ledger: SessionLedger | None = None) -> None:
        self.spec = spec
        self.ledger = ledger if ledger is not None else SessionLedger()

    def analyse(self, trace: Trace) -> list[Finding]:
        findings: list[Finding] = []
        try:
            if trace is not None:
                steps = getattr(trace, "steps", [])

                # 1. L0.STEP_ORDER: step indices are not 0..N-1 in order
                if isinstance(steps, list) and len(steps) > 0:
                    indices = [getattr(s, "index", None) for s in steps]
                    expected_indices = list(range(len(steps)))
                    if indices != expected_indices:
                        first_bad_step = next(
                            (idx for idx, exp in zip(indices, expected_indices) if idx != exp),
                            None,
                        )
                        findings.append(
                            Finding(
                                code="L0.STEP_ORDER",
                                severity="critical",
                                message=(
                                    f"Step indices are not 0..{len(steps) - 1} in order "
                                    f"(found: {indices})"
                                ),
                                step=first_bad_step if isinstance(first_bad_step, int) else None,
                                evidence={
                                    "found_indices": indices,
                                    "expected_indices": expected_indices,
                                },
                            )
                        )

                # 2. L0.PROCEDURE_ORDER: procedures appear in an order inconsistent with the spec:
                # the first occurrence of INIT must precede SIGN, which must precede VERIFY
                if isinstance(steps, list) and len(steps) > 0:
                    first_init = None
                    first_sign = None
                    first_verify = None
                    for i, s in enumerate(steps):
                        proc = getattr(s, "procedure", None)
                        proc_val = proc.value if hasattr(proc, "value") else str(proc) if proc else ""
                        if proc_val == "INIT" and first_init is None:
                            first_init = i
                        elif proc_val == "SIGN" and first_sign is None:
                            first_sign = i
                        elif proc_val == "VERIFY" and first_verify is None:
                            first_verify = i

                    order_violated = False
                    violation_msg = ""
                    bad_step = None
                    if first_init is not None and first_sign is not None and first_init > first_sign:
                        order_violated = True
                        violation_msg = (
                            f"first occurrence of INIT (step {first_init}) appears after "
                            f"SIGN (step {first_sign})"
                        )
                        bad_step = first_init
                    elif first_sign is not None and first_verify is not None and first_sign > first_verify:
                        order_violated = True
                        violation_msg = (
                            f"first occurrence of SIGN (step {first_sign}) appears after "
                            f"VERIFY (step {first_verify})"
                        )
                        bad_step = first_sign
                    elif first_init is not None and first_verify is not None and first_init > first_verify:
                        order_violated = True
                        violation_msg = (
                            f"first occurrence of INIT (step {first_init}) appears after "
                            f"VERIFY (step {first_verify})"
                        )
                        bad_step = first_init

                    if order_violated:
                        findings.append(
                            Finding(
                                code="L0.PROCEDURE_ORDER",
                                severity="critical",
                                message=f"Procedure order inconsistent with spec: {violation_msg}",
                                step=bad_step,
                                evidence={
                                    "first_init": first_init,
                                    "first_sign": first_sign,
                                    "first_verify": first_verify,
                                },
                            )
                        )

                # 3. L0.SPEC_DIVERGENCE: the trace step sequence (procedure,party,action)
                # does not match the spec step sequence element-wise
                if self.spec is not None and hasattr(self.spec, "steps") and isinstance(self.spec.steps, list):
                    spec_steps = self.spec.steps
                    if len(steps) != len(spec_steps):
                        findings.append(
                            Finding(
                                code="L0.SPEC_DIVERGENCE",
                                severity="critical",
                                message=(
                                    f"Trace step count ({len(steps)}) does not match "
                                    f"spec step count ({len(spec_steps)})"
                                ),
                                step=None,
                                evidence={
                                    "trace_step_count": len(steps),
                                    "spec_step_count": len(spec_steps),
                                },
                            )
                        )

                    for i in range(min(len(steps), len(spec_steps))):
                        ts = steps[i]
                        ss = spec_steps[i]
                        t_proc = getattr(ts, "procedure", None)
                        t_proc_val = (
                            t_proc.value if hasattr(t_proc, "value") else str(t_proc) if t_proc else ""
                        )
                        s_proc = getattr(ss, "procedure", None)
                        s_proc_val = (
                            s_proc.value if hasattr(s_proc, "value") else str(s_proc) if s_proc else ""
                        )

                        t_party = getattr(ts, "party", None)
                        t_party_val = (
                            t_party.value if hasattr(t_party, "value") else str(t_party) if t_party else ""
                        )
                        s_party = getattr(ss, "party", None)
                        s_party_val = (
                            s_party.value if hasattr(s_party, "value") else str(s_party) if s_party else ""
                        )

                        t_act = getattr(ts, "action", None)
                        t_act_val = (
                            t_act.value if hasattr(t_act, "value") else str(t_act) if t_act else ""
                        )
                        s_act = getattr(ss, "action", None)
                        s_act_val = (
                            s_act.value if hasattr(s_act, "value") else str(s_act) if s_act else ""
                        )

                        if (t_proc_val, t_party_val, t_act_val) != (s_proc_val, s_party_val, s_act_val):
                            findings.append(
                                Finding(
                                    code="L0.SPEC_DIVERGENCE",
                                    severity="critical",
                                    message=(
                                        f"Step {i} sequence ({t_proc_val}, {t_party_val}, {t_act_val}) "
                                        f"does not match spec ({s_proc_val}, {s_party_val}, {s_act_val})"
                                    ),
                                    step=i,
                                    evidence={
                                        "step": i,
                                        "trace": (t_proc_val, t_party_val, t_act_val),
                                        "spec": (s_proc_val, s_party_val, s_act_val),
                                    },
                                )
                            )

                # 4. L0.UNDECLARED_REGISTER / L0.UNDECLARED_KEY / 5. L0.REGISTER_AFTER_CONSUME
                declared_registers: set[str] = set()
                consumed_map: dict[str, int | None] = {}
                for r in getattr(trace, "registers", []):
                    r_name = (
                        getattr(r, "name", None)
                        if hasattr(r, "name")
                        else (r.get("name") if isinstance(r, dict) else None)
                    )
                    if r_name:
                        declared_registers.add(str(r_name))
                        consumed_map[str(r_name)] = (
                            getattr(r, "consumed_step", None)
                            if hasattr(r, "consumed_step")
                            else (r.get("consumed_step") if isinstance(r, dict) else None)
                        )

                declared_keys: set[str] = set()
                for k in getattr(trace, "keys", []):
                    k_name = (
                        getattr(k, "name", None)
                        if hasattr(k, "name")
                        else (k.get("name") if isinstance(k, dict) else None)
                    )
                    if k_name:
                        declared_keys.add(str(k_name))

                for s in steps:
                    s_idx = getattr(s, "index", None)
                    # Check registers
                    s_regs = getattr(s, "registers", [])
                    if isinstance(s_regs, list):
                        for reg in s_regs:
                            reg_str = str(reg)
                            if reg_str not in declared_registers:
                                findings.append(
                                    Finding(
                                        code="L0.UNDECLARED_REGISTER",
                                        severity="critical",
                                        message=f"Step {s_idx} references undeclared register '{reg_str}'",
                                        step=s_idx if isinstance(s_idx, int) else None,
                                        evidence={"register": reg_str, "step": s_idx},
                                    )
                                )
                            elif isinstance(s_idx, int):
                                c_step = consumed_map.get(reg_str)
                                if c_step is not None and s_idx > c_step:
                                    findings.append(
                                        Finding(
                                            code="L0.REGISTER_AFTER_CONSUME",
                                            severity="critical",
                                            message=(
                                                f"Register '{reg_str}' is used at step {s_idx} "
                                                f"after its consumed_step {c_step}"
                                            ),
                                            step=s_idx,
                                            evidence={
                                                "register": reg_str,
                                                "step": s_idx,
                                                "consumed_step": c_step,
                                            },
                                        )
                                    )

                    # Check keys
                    s_keys = getattr(s, "keys_used", [])
                    if isinstance(s_keys, list):
                        for key in s_keys:
                            key_str = str(key)
                            if key_str not in declared_keys:
                                findings.append(
                                    Finding(
                                        code="L0.UNDECLARED_KEY",
                                        severity="critical",
                                        message=f"Step {s_idx} references undeclared key '{key_str}'",
                                        step=s_idx if isinstance(s_idx, int) else None,
                                        evidence={"key": key_str, "step": s_idx},
                                    )
                                )

                # 6. L0.REPLAY_SESSION: trace.session_id already recorded in ledger
                session_id = getattr(trace, "session_id", None)
                if session_id and self.ledger.seen_session(str(session_id)):
                    findings.append(
                        Finding(
                            code="L0.REPLAY_SESSION",
                            severity="critical",
                            message=(
                                f"Session ID '{session_id}' already recorded in previous run "
                                f"(replay attack detected)"
                            ),
                            step=None,
                            evidence={"session_id": str(session_id)},
                        )
                    )

                # 7. L0.REPLAY_NONCE: trace.nonce already recorded in ledger
                nonce = getattr(trace, "nonce", None)
                if nonce and self.ledger.seen_nonce(str(nonce)):
                    findings.append(
                        Finding(
                            code="L0.REPLAY_NONCE",
                            severity="critical",
                            message=(
                                f"Nonce '{nonce}' already recorded in previous run "
                                f"(replay attack detected)"
                            ),
                            step=None,
                            evidence={"nonce": str(nonce)},
                        )
                    )

                # 8. L0.KEY_REUSE / L0.NO_KEY_BINDING: single-use key enforcement on key material
                keys = getattr(trace, "keys", [])
                key_digests = getattr(trace, "key_digests", {})

                # Collect single-use key names
                single_use_keys: list[str] = []
                if isinstance(keys, list):
                    for k in keys:
                        k_name = (
                            getattr(k, "name", None)
                            if hasattr(k, "name")
                            else (k.get("name") if isinstance(k, dict) else None)
                        )
                        k_policy = (
                            getattr(k, "reuse_policy", None)
                            if hasattr(k, "reuse_policy")
                            else (k.get("reuse_policy") if isinstance(k, dict) else None)
                        )
                        if k_name and k_policy == "single-use":
                            single_use_keys.append(str(k_name))

                if single_use_keys:
                    if not key_digests or not isinstance(key_digests, dict):
                        # Absence of key binding is not evidence of reuse
                        findings.append(
                            Finding(
                                code="L0.NO_KEY_BINDING",
                                severity="warning",
                                message=(
                                    "Trace does not bind key material (key_digests is empty); "
                                    "single-use key enforcement cannot be evaluated"
                                ),
                                step=None,
                                evidence={"single_use_keys": single_use_keys},
                            )
                        )
                    else:
                        for k_name in single_use_keys:
                            digest = key_digests.get(k_name)
                            if digest:
                                uses = self.ledger.key_material_uses(k_name, str(digest))
                                if uses > 0:
                                    findings.append(
                                        Finding(
                                            code="L0.KEY_REUSE",
                                            severity="critical",
                                            message=(
                                                f"Key '{k_name}' with digest '{digest}' declared as single-use "
                                                f"has already been used in {uses} previous run(s) (key material reuse detected)"
                                            ),
                                            step=None,
                                            evidence={
                                                "key": k_name,
                                                "digest": str(digest),
                                                "previous_uses": uses,
                                            },
                                        )
                                    )

                # 9. L0.UNAUTHORIZED_VERIFIER: a VERIFY or PROOF_OF_RECEIPT step performed by
                # a party that is NOT in spec.verifier_set (and is not Trent)
                raw_verifiers = []
                if self.spec is not None and hasattr(self.spec, "verifier_set") and isinstance(self.spec.verifier_set, list):
                    raw_verifiers = self.spec.verifier_set
                elif hasattr(trace, "verifier_set") and isinstance(trace.verifier_set, list):
                    raw_verifiers = trace.verifier_set

                verifier_names: set[str] = set()
                for v in raw_verifiers:
                    v_val = v.value if hasattr(v, "value") else str(v)
                    verifier_names.add(v_val)

                # Trent is always permitted to arbitrate
                allowed_verify_parties = verifier_names | {"Trent", Party.TRENT.value}
                # For PROOF_OF_RECEIPT, Alice (the signer/sender receiving receipt acknowledgment) is authorized
                allowed_receipt_parties = allowed_verify_parties | {"Alice", Party.ALICE.value}

                for s in steps:
                    s_proc = getattr(s, "procedure", None)
                    s_proc_val = s_proc.value if hasattr(s_proc, "value") else str(s_proc) if s_proc else ""
                    s_party = getattr(s, "party", None)
                    s_party_val = s_party.value if hasattr(s_party, "value") else str(s_party) if s_party else ""
                    s_idx = getattr(s, "index", None)

                    if s_proc_val == "VERIFY":
                        if s_party_val not in allowed_verify_parties:
                            findings.append(
                                Finding(
                                    code="L0.UNAUTHORIZED_VERIFIER",
                                    severity="critical",
                                    message=(
                                        f"Step {s_idx} ({s_proc_val}) performed by unauthorized verifier party '{s_party_val}' "
                                        f"(authorized verifiers: {sorted(allowed_verify_parties)})"
                                    ),
                                    step=s_idx if isinstance(s_idx, int) else None,
                                    evidence={
                                        "step": s_idx,
                                        "procedure": s_proc_val,
                                        "party": s_party_val,
                                        "authorized": sorted(allowed_verify_parties),
                                    },
                                )
                            )
                    elif s_proc_val == "PROOF_OF_RECEIPT":
                        if s_party_val not in allowed_receipt_parties:
                            findings.append(
                                Finding(
                                    code="L0.UNAUTHORIZED_VERIFIER",
                                    severity="critical",
                                    message=(
                                        f"Step {s_idx} ({s_proc_val}) performed by unauthorized party '{s_party_val}' "
                                        f"(authorized: {sorted(allowed_receipt_parties)})"
                                    ),
                                    step=s_idx if isinstance(s_idx, int) else None,
                                    evidence={
                                        "step": s_idx,
                                        "procedure": s_proc_val,
                                        "party": s_party_val,
                                        "authorized": sorted(allowed_receipt_parties),
                                    },
                                )
                            )

            # 10. L0.MISSING_PROCEDURE: the spec claims non_repudiation_origin but has no
            # PROOF_OF_ORIGIN procedure, or claims non_repudiation_receipt with no PROOF_OF_RECEIPT.
            # Severity "warning". Message must say that the claim is unsupported by the specification itself.
            if self.spec is not None:
                claims = getattr(self.spec, "claims", [])
                if isinstance(claims, list):
                    has_origin = False
                    has_receipt = False
                    if hasattr(self.spec, "has_procedure"):
                        has_origin = self.spec.has_procedure("PROOF_OF_ORIGIN")
                        has_receipt = self.spec.has_procedure("PROOF_OF_RECEIPT")
                    elif hasattr(self.spec, "steps") and isinstance(self.spec.steps, list):
                        for s in self.spec.steps:
                            p = getattr(s, "procedure", None)
                            pval = p.value if hasattr(p, "value") else str(p)
                            if pval == "PROOF_OF_ORIGIN":
                                has_origin = True
                            elif pval == "PROOF_OF_RECEIPT":
                                has_receipt = True

                    if "non_repudiation_origin" in claims and not has_origin:
                        findings.append(
                            Finding(
                                code="L0.MISSING_PROCEDURE",
                                severity="warning",
                                message=(
                                    "Claim 'non_repudiation_origin' is unsupported by the "
                                    "specification itself: missing PROOF_OF_ORIGIN procedure"
                                ),
                                step=None,
                                evidence={
                                    "claim": "non_repudiation_origin",
                                    "missing_procedure": "PROOF_OF_ORIGIN",
                                },
                            )
                        )

                    if "non_repudiation_receipt" in claims and not has_receipt:
                        findings.append(
                            Finding(
                                code="L0.MISSING_PROCEDURE",
                                severity="warning",
                                message=(
                                    "Claim 'non_repudiation_receipt' is unsupported by the "
                                    "specification itself: missing PROOF_OF_RECEIPT procedure"
                                ),
                                step=None,
                                evidence={
                                    "claim": "non_repudiation_receipt",
                                    "missing_procedure": "PROOF_OF_RECEIPT",
                                },
                            )
                        )

        except Exception as exc:
            # analyse() must NEVER raise
            findings.append(
                Finding(
                    code="L0.INTERNAL_ERROR",
                    severity="warning",
                    message=f"Internal error during L0 analysis: {exc}",
                    step=None,
                    evidence={"error": str(exc)},
                )
            )

        # Record trace into ledger AFTER analysing so run does not flag itself
        try:
            if self.ledger is not None and trace is not None:
                self.ledger.record(trace)
        except Exception:
            pass

        return findings


def analyse_stream(spec: SchemeSpec | None, traces: list[Trace]) -> list[list[Finding]]:
    """Fresh ledger, analyse each trace in order. Replaying trace k after trace k triggers replay."""
    ledger = SessionLedger()
    l0 = Layer0(spec=spec, ledger=ledger)
    return [l0.analyse(t) for t in traces]
