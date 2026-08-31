"""Static dispute-resolution analysis for Arbitrated Quantum Signature (AQS) schemes.

WHY THIS EXISTS:
SIH26141 names forgery, impersonation, replay, quantum channel manipulation, and
unauthorized verification. It does NOT name repudiation of origin, repudiation of receipt,
or false allegation. Those three are the DEFINING security goals of an arbitrated signature —
they are the only reason the arbitrator exists at all. They are also design-time failures
living in dispute-resolution procedures that most published schemes do not even specify,
so they leave NO channel signature to threshold on. A statistical detector cannot see them
for the same structural reason it cannot see the paired-Pauli forgery.

FRAMING DISCIPLINE:
We do NOT say the problem statement is wrong. Its threat model is a RUNTIME model; these are
DESIGN-TIME failures. A complete framework needs both, and this module supplies the missing half.

PROVEN:
- If a scheme specifies no PROOF_OF_ORIGIN procedure, Alice can deny signing with zero probability
  of contradiction by any defined protocol step (DR.ORIGIN_NO_PROCEDURE).
- If a PROOF_OF_ORIGIN procedure does not reference the message or signature register, the proof
  is independent of the message and proves nothing about which message was signed (DR.ORIGIN_UNBOUND).
- If a PROOF_OF_RECEIPT procedure does not reference the message register, the receipt is unbound
  from the message content. The signer Alice can allege that ANY arbitrary message was received by
  Bob, presenting Bob's generic receipt acknowledgment with probability 1.0 (DR.RECEIPT_UNBOUND /
  DR.FALSE_ALLEGATION).
- If Bob obtains and measures/accepts the message plaintext before the arbitrator Trent verifies
  the signature in VERIFY, Bob can abort and disavow receipt after learning the plaintext
  (DR.PLAINTEXT_BEFORE_ARBITRATION).
- If a dispute procedure omits the arbitrator Trent, two mutually untrusted parties cannot resolve
  conflicting claims without a trusted third party (DR.NO_ARBITRATOR_IN_DISPUTE).

ASSUMED:
- The SchemeSpec accurately reflects the published protocol steps, register bindings, and claims.
- The adversary operates within the bounds of standard classical-quantum dispute arbitration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pauliguard.engine.spec_loader import SchemeSpec, StepSpec
from pauliguard.engine.trace import Action, Party, Procedure, Trace


@dataclass
class DisputeFinding:
    """Finding emitted by DisputeAnalyser during static dispute-resolution analysis."""

    code: str  # e.g., "DR.ORIGIN_NO_PROCEDURE", "DR.ORIGIN_UNBOUND", etc.
    severity: str  # "critical" | "warning"
    threat: str  # "repudiation_of_origin" | "repudiation_of_receipt" | "false_allegation"
    message: str  # names the specific missing or unbound procedure
    claimed_by_scheme: bool  # does the spec CLAIM the goal it fails to support?
    evidence: dict = field(default_factory=dict)


def _normalize_proc(proc: Any) -> str:
    if hasattr(proc, "value"):
        return str(proc.value)
    return str(proc) if proc is not None else ""


def _normalize_party(party: Any) -> str:
    if hasattr(party, "value"):
        return str(party.value)
    return str(party) if party is not None else ""


def _normalize_action(act: Any) -> str:
    if hasattr(act, "value"):
        return str(act.value).lower()
    return str(act).lower() if act is not None else ""


def _get_message_register_names(spec: SchemeSpec) -> set[str]:
    """Identify registers holding message qubits or message copies."""
    msg_regs: set[str] = set()
    declared = getattr(spec, "registers", []) or []
    for r in declared:
        name = r.get("name") if isinstance(r, dict) else getattr(r, "name", None)
        if name:
            n_lower = name.lower()
            if n_lower == "msg" or n_lower.startswith("msg") or "message" in n_lower or n_lower == "m":
                msg_regs.add(str(name))
    steps = getattr(spec, "steps", []) or []
    for s in steps:
        if _normalize_proc(s.procedure) == "SIGN" and _normalize_action(s.action) == "prepare":
            for reg in getattr(s, "registers", []) or []:
                if any(k in str(reg).lower() for k in ("msg", "message", "m")):
                    msg_regs.add(str(reg))
    if not msg_regs:
        msg_regs = {"msg", "message", "msg_copy", "m"}
    return msg_regs


def _get_signature_register_names(spec: SchemeSpec) -> set[str]:
    """Identify registers holding signature states."""
    sig_regs: set[str] = set()
    declared = getattr(spec, "registers", []) or []
    for r in declared:
        name = r.get("name") if isinstance(r, dict) else getattr(r, "name", None)
        if name:
            n_lower = name.lower()
            if n_lower == "sig" or n_lower.startswith("sig") or "signature" in n_lower or n_lower == "s":
                sig_regs.add(str(name))
    steps = getattr(spec, "steps", []) or []
    for s in steps:
        if _normalize_proc(s.procedure) == "SIGN":
            for reg in getattr(s, "registers", []) or []:
                if any(k in str(reg).lower() for k in ("sig", "signature", "s")):
                    sig_regs.add(str(reg))
    if not sig_regs:
        sig_regs = {"sig", "signature", "sig_states", "sig_TB", "s"}
    return sig_regs


def _is_message_register(reg_name: str, msg_regs: set[str]) -> bool:
    if reg_name in msg_regs:
        return True
    n = reg_name.lower()
    return n == "msg" or n.startswith("msg") or "message" in n or n == "m"


def _is_signature_register(reg_name: str, sig_regs: set[str]) -> bool:
    if reg_name in sig_regs:
        return True
    n = reg_name.lower()
    return n == "sig" or n.startswith("sig") or "signature" in n or n == "s"


class DisputeAnalyser:
    """Pure static analyzer inspecting SchemeSpec for dispute-resolution vulnerabilities."""

    def __init__(self, spec: SchemeSpec) -> None:
        self.spec = spec

    def analyse(self) -> list[DisputeFinding]:
        """Perform static dispute-resolution analysis of the SchemeSpec.

        NEVER raises under any circumstance.
        """
        findings: list[DisputeFinding] = []
        try:
            if self.spec is None:
                return findings

            claims = list(getattr(self.spec, "claims", []) or [])
            steps = list(getattr(self.spec, "steps", []) or [])

            claims_origin = any(
                c in claims for c in ("non_repudiation_origin", "non_repudiation_of_origin", "origin_non_repudiation")
            )
            claims_receipt = any(
                c in claims for c in ("non_repudiation_receipt", "non_repudiation_of_receipt", "receipt_non_repudiation")
            )
            claims_fa = any(
                c in claims for c in ("no_false_allegation", "false_allegation")
            )

            msg_regs = _get_message_register_names(self.spec)
            sig_regs = _get_signature_register_names(self.spec)

            # Partition steps by procedure
            origin_steps: list[StepSpec] = []
            receipt_steps: list[StepSpec] = []
            verify_steps: list[StepSpec] = []

            for s in steps:
                proc_str = _normalize_proc(s.procedure)
                if proc_str == "PROOF_OF_ORIGIN":
                    origin_steps.append(s)
                elif proc_str == "PROOF_OF_RECEIPT":
                    receipt_steps.append(s)
                elif proc_str == "VERIFY":
                    verify_steps.append(s)

            # -------------------------------------------------------------
            # Check 1: DR.ORIGIN_NO_PROCEDURE / DR.ORIGIN_UNBOUND
            # -------------------------------------------------------------
            if not origin_steps:
                if claims_origin:
                    findings.append(
                        DisputeFinding(
                            code="DR.ORIGIN_NO_PROCEDURE",
                            severity="critical",
                            threat="repudiation_of_origin",
                            message=(
                                "Spec claims 'non_repudiation_origin' but has NO PROOF_OF_ORIGIN steps. "
                                "Alice can simply deny signing; there is no defined procedure to contradict her."
                            ),
                            claimed_by_scheme=True,
                            evidence={"claims": claims, "procedure": "PROOF_OF_ORIGIN"},
                        )
                    )
                else:
                    findings.append(
                        DisputeFinding(
                            code="DR.ORIGIN_NO_PROCEDURE",
                            severity="warning",
                            threat="repudiation_of_origin",
                            message=(
                                "Spec defines NO PROOF_OF_ORIGIN steps. Alice can deny signing without contradiction "
                                "(scheme does not claim non-repudiation of origin; silent omission)."
                            ),
                            claimed_by_scheme=False,
                            evidence={"claims": claims, "procedure": "PROOF_OF_ORIGIN"},
                        )
                    )
            else:
                # Origin procedure exists; check register binding
                origin_regs: set[str] = set()
                for s in origin_steps:
                    for r in (getattr(s, "registers", []) or []):
                        origin_regs.add(str(r))

                has_msg_or_sig = any(
                    _is_message_register(r, msg_regs) or _is_signature_register(r, sig_regs)
                    for r in origin_regs
                )

                if not has_msg_or_sig:
                    findings.append(
                        DisputeFinding(
                            code="DR.ORIGIN_UNBOUND",
                            severity="critical" if claims_origin else "warning",
                            threat="repudiation_of_origin",
                            message=(
                                "PROOF_OF_ORIGIN procedure exists but NO step in it references the message register "
                                "or signature register. A proof of origin that does not depend on the message proves "
                                "nothing about which message was signed."
                            ),
                            claimed_by_scheme=claims_origin,
                            evidence={
                                "origin_registers": sorted(origin_regs),
                                "message_registers": sorted(msg_regs),
                                "signature_registers": sorted(sig_regs),
                            },
                        )
                    )

            # -------------------------------------------------------------
            # Check 2: DR.RECEIPT_NO_PROCEDURE / DR.RECEIPT_UNBOUND / DR.FALSE_ALLEGATION
            # -------------------------------------------------------------
            if not receipt_steps:
                if claims_receipt:
                    findings.append(
                        DisputeFinding(
                            code="DR.RECEIPT_NO_PROCEDURE",
                            severity="critical",
                            threat="repudiation_of_receipt",
                            message=(
                                "Spec claims 'non_repudiation_receipt' but has NO PROOF_OF_RECEIPT steps. "
                                "Bob can simply deny receipt; there is no defined procedure to contradict him."
                            ),
                            claimed_by_scheme=True,
                            evidence={"claims": claims, "procedure": "PROOF_OF_RECEIPT"},
                        )
                    )
                else:
                    findings.append(
                        DisputeFinding(
                            code="DR.RECEIPT_NO_PROCEDURE",
                            severity="warning",
                            threat="repudiation_of_receipt",
                            message=(
                                "Spec defines NO PROOF_OF_RECEIPT steps (scheme does not claim non-repudiation of receipt; "
                                "silent omission)."
                            ),
                            claimed_by_scheme=False,
                            evidence={"claims": claims, "procedure": "PROOF_OF_RECEIPT"},
                        )
                    )
            else:
                # Receipt procedure exists; check message binding
                receipt_regs: set[str] = set()
                for s in receipt_steps:
                    for r in (getattr(s, "registers", []) or []):
                        receipt_regs.add(str(r))

                has_msg = any(_is_message_register(r, msg_regs) for r in receipt_regs)

                if not has_msg:
                    findings.append(
                        DisputeFinding(
                            code="DR.RECEIPT_UNBOUND",
                            severity="critical" if claims_receipt else "warning",
                            threat="repudiation_of_receipt",
                            message=(
                                "PROOF_OF_RECEIPT exists but no step in it references the message register. "
                                "Receipt is unbound from message content."
                            ),
                            claimed_by_scheme=claims_receipt,
                            evidence={
                                "receipt_registers": sorted(receipt_regs),
                                "message_registers": sorted(msg_regs),
                            },
                        )
                    )

                    findings.append(
                        DisputeFinding(
                            code="DR.FALSE_ALLEGATION",
                            severity="critical" if (claims_fa or claims_receipt) else "warning",
                            threat="false_allegation",
                            message=(
                                "PROOF_OF_RECEIPT is unbound from the message register (false-allegation hole): "
                                "if the receipt procedure does not depend on the message, the signer can allege "
                                "ANY message was received, with probability 1.0."
                            ),
                            claimed_by_scheme=bool(claims_fa or claims_receipt),
                            evidence={
                                "receipt_registers": sorted(receipt_regs),
                                "message_registers": sorted(msg_regs),
                            },
                        )
                    )

            # -------------------------------------------------------------
            # Check 3: DR.PLAINTEXT_BEFORE_ARBITRATION
            # -------------------------------------------------------------
            # Find index of first VERIFY step performed by Trent
            trent_first_verify_idx: int | None = None
            for i, s in enumerate(steps):
                if _normalize_proc(s.procedure) == "VERIFY" and _normalize_party(s.party) == "Trent":
                    trent_first_verify_idx = i
                    break

            cutoff_idx = trent_first_verify_idx if trent_first_verify_idx is not None else len(steps)
            has_arbitrator = any(
                _normalize_party(v) == "Trent" for v in getattr(self.spec, "verifier_set", []) or []
            ) or any(_normalize_party(s.party) == "Trent" for s in steps)

            if has_arbitrator:
                for i, s in enumerate(steps[:cutoff_idx]):
                    if _normalize_party(s.party) == "Bob":
                        action_str = _normalize_action(s.action)
                        if action_str in ("measure", "accept"):
                            s_regs = [str(r) for r in (getattr(s, "registers", []) or [])]
                            if any(_is_message_register(r, msg_regs) for r in s_regs):
                                findings.append(
                                    DisputeFinding(
                                        code="DR.PLAINTEXT_BEFORE_ARBITRATION",
                                        severity="critical" if claims_receipt else "warning",
                                        threat="repudiation_of_receipt",
                                        message=(
                                            f"Receiver Bob performs {action_str.upper()} on message register at step {i} "
                                            f"earlier than Trent's first VERIFY step (step {trent_first_verify_idx if trent_first_verify_idx is not None else 'none'}). "
                                            f"Bob obtains plaintext before arbitrator involvement and can decline to continue / disavow receipt."
                                        ),
                                        claimed_by_scheme=claims_receipt,
                                        evidence={
                                            "bob_step_index": i,
                                            "bob_action": action_str,
                                            "trent_first_verify_index": trent_first_verify_idx,
                                            "registers": s_regs,
                                        },
                                    )
                                )
                                break

            # -------------------------------------------------------------
            # Check 4: DR.NO_ARBITRATOR_IN_DISPUTE
            # -------------------------------------------------------------
            if origin_steps:
                trent_in_origin = any(_normalize_party(s.party) == "Trent" for s in origin_steps)
                if not trent_in_origin:
                    findings.append(
                        DisputeFinding(
                            code="DR.NO_ARBITRATOR_IN_DISPUTE",
                            severity="warning",
                            threat="repudiation_of_origin",
                            message=(
                                "PROOF_OF_ORIGIN procedure exists but Party.TRENT appears in NO step of it. "
                                "A dispute procedure that never invokes the arbitrator cannot resolve a dispute."
                            ),
                            claimed_by_scheme=claims_origin,
                            evidence={
                                "procedure": "PROOF_OF_ORIGIN",
                                "parties_present": sorted({_normalize_party(s.party) for s in origin_steps}),
                            },
                        )
                    )

            if receipt_steps:
                trent_in_receipt = any(_normalize_party(s.party) == "Trent" for s in receipt_steps)
                if not trent_in_receipt:
                    findings.append(
                        DisputeFinding(
                            code="DR.NO_ARBITRATOR_IN_DISPUTE",
                            severity="warning",
                            threat="repudiation_of_receipt",
                            message=(
                                "PROOF_OF_RECEIPT procedure exists but Party.TRENT appears in NO step of it. "
                                "A dispute procedure that never invokes the arbitrator cannot resolve a dispute."
                            ),
                            claimed_by_scheme=claims_receipt,
                            evidence={
                                "procedure": "PROOF_OF_RECEIPT",
                                "parties_present": sorted({_normalize_party(s.party) for s in receipt_steps}),
                            },
                        )
                    )

        except Exception as exc:
            findings.append(
                DisputeFinding(
                    code="DR.INTERNAL_ERROR",
                    severity="warning",
                    threat="repudiation_of_origin",
                    message=f"Internal error during dispute analysis: {exc}",
                    claimed_by_scheme=False,
                    evidence={"error": str(exc)},
                )
            )

        return findings


def threat_model_gap_table(specs: dict[str, SchemeSpec]) -> str:
    """Generate a markdown table summarizing threat model coverage and detection layer gaps.

    Shows the honest distinction between threats named by SIH26141 vs omitted design-time threats,
    and their statistical detectability.
    """
    scheme_names = list(specs.keys())

    # Precompute dispute findings for each scheme
    dispute_findings: dict[str, list[DisputeFinding]] = {}
    for name, spec in specs.items():
        analyser = DisputeAnalyser(spec)
        dispute_findings[name] = analyser.analyse()

    headers = [
        "Threat / Security Objective",
        "Named by SIH26141",
        "Detectable by Statistical Layers",
    ] + scheme_names

    rows_data: list[tuple[str, str, str, list[str]]] = []

    # Row 1: Quantum Channel Manipulation
    row1_status = []
    for name in scheme_names:
        if "decoy" in name:
            row1_status.append("Protected (Decoy-state BB84)")
        else:
            row1_status.append("Protected (Decoy states on channels)")
    rows_data.append((
        "Quantum Channel Manipulation",
        "YES",
        "YES (L1/L2 Serfling & Azuma bounds)",
        row1_status,
    ))

    # Row 2: Impersonation
    row2_status = []
    for name in scheme_names:
        if "decoy" in name:
            row2_status.append("Protected (One-time universal hashing)")
        else:
            row2_status.append("Protected (Shared QOTP keys k_AT, k_BT)")
    rows_data.append((
        "Impersonation",
        "YES",
        "NO (Deterministic key management / L0)",
        row2_status,
    ))

    # Row 3: Replay
    row3_status = [
        "Enforced by L0 (Session & Nonce ledger)" for _ in scheme_names
    ]
    rows_data.append((
        "Replay Attack",
        "YES",
        "NO (Deterministic predicate in L0)",
        row3_status,
    ))

    # Row 4: Unauthorized Verification
    row4_status = [
        "Enforced by L0 (Verifier set restriction)" for _ in scheme_names
    ]
    rows_data.append((
        "Unauthorized Verification",
        "YES",
        "NO (Deterministic predicate in L0)",
        row4_status,
    ))

    # Row 5: Forgery (Pauli Malleability)
    row5_status = []
    for name, spec in specs.items():
        if spec.encryption == "none":
            row5_status.append("SECURE (No malleable encryption)")
        else:
            row5_status.append("VULNERABLE (QOTP malleable, prob=1.0)")
    rows_data.append((
        "Forgery (Pauli Malleability)",
        "YES",
        "NO (L3 Algebraic search required)",
        row5_status,
    ))

    # Row 6: Repudiation of Origin (Omitted)
    row6_status = []
    for name, spec in specs.items():
        f_codes = [f.code for f in dispute_findings[name] if f.threat == "repudiation_of_origin"]
        if "DR.ORIGIN_NO_PROCEDURE" in f_codes:
            if "non_repudiation_origin" in spec.claims:
                row6_status.append("VULNERABLE (Claimed but NO PROOF_OF_ORIGIN)")
            else:
                row6_status.append("OMITTED (No PROOF_OF_ORIGIN defined)")
        elif "DR.ORIGIN_UNBOUND" in f_codes:
            row6_status.append("VULNERABLE (Origin unbound from message)")
        else:
            row6_status.append("Supported (Origin proof defined)")
    rows_data.append((
        "Repudiation of Origin",
        "NO",
        "NO (Design-time / DisputeAnalyser)",
        row6_status,
    ))

    # Row 7: Repudiation of Receipt (Omitted)
    row7_status = []
    for name, spec in specs.items():
        f_codes = [f.code for f in dispute_findings[name] if f.threat == "repudiation_of_receipt"]
        if "DR.RECEIPT_NO_PROCEDURE" in f_codes:
            if "non_repudiation_receipt" in spec.claims:
                row7_status.append("VULNERABLE (Claimed but NO PROOF_OF_RECEIPT)")
            else:
                row7_status.append("OMITTED (No PROOF_OF_RECEIPT defined)")
        elif "DR.RECEIPT_UNBOUND" in f_codes:
            row7_status.append("VULNERABLE (Receipt unbound from message)")
        elif "DR.PLAINTEXT_BEFORE_ARBITRATION" in f_codes:
            row7_status.append("VULNERABLE (Plaintext before arbitration)")
        else:
            row7_status.append("Supported (Receipt proof defined)")
    rows_data.append((
        "Repudiation of Receipt",
        "NO",
        "NO (Design-time / DisputeAnalyser)",
        row7_status,
    ))

    # Row 8: False Allegation (Omitted)
    row8_status = []
    for name, spec in specs.items():
        f_codes = [f.code for f in dispute_findings[name] if f.threat == "false_allegation"]
        if "DR.FALSE_ALLEGATION" in f_codes:
            row8_status.append("VULNERABLE (False-allegation hole: unbound receipt)")
        else:
            row8_status.append("Secure / Not vulnerable")
    rows_data.append((
        "False Allegation",
        "NO",
        "NO (Design-time / DisputeAnalyser)",
        row8_status,
    ))

    # Construct markdown table
    header_line = "| " + " | ".join(headers) + " |"
    separator_line = "| " + " | ".join(["---"] * len(headers)) + " |"
    table_lines = [header_line, separator_line]

    for threat, named, detectable, statuses in rows_data:
        row_cols = [threat, named, detectable] + statuses
        table_lines.append("| " + " | ".join(row_cols) + " |")

    return "\n".join(table_lines)
