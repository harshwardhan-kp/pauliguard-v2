"""Attacks against Arbitrated Quantum Signature (AQS) schemes."""

from pauliguard.attacks.paired_pauli import (
    ForgeryWitness,
    forged_and_honest_density_matrices,
    paired_pauli_attack,
    predicate_holds,
    step1_clifford_conjugate_is_pauli,
    step2_predicate_holds,
    step3_qotp_letters_preserved,
    step4_density_matrices,
)
from pauliguard.attacks.repudiation import (
    DisputeAnalyser,
    DisputeFinding,
    threat_model_gap_table,
)

__all__ = [
    "ForgeryWitness",
    "paired_pauli_attack",
    "predicate_holds",
    "forged_and_honest_density_matrices",
    "step1_clifford_conjugate_is_pauli",
    "step2_predicate_holds",
    "step3_qotp_letters_preserved",
    "step4_density_matrices",
    "DisputeFinding",
    "DisputeAnalyser",
    "threat_model_gap_table",
]
