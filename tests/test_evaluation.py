"""Test suite for the PauliGuard evaluation harness (Deliverable D7).

Verifies:
1. evaluate() at trials=60 returns a matrix whose every cell has trials>0 and 0<=rate<=1,
   and whose ci_low <= rate <= ci_high.
2. The L1 cell on paired_pauli_X is EXACTLY 0.0 and the L1 cell on intercept_resend is EXACTLY 1.0.
3. The L0 cell on replay is 1.0 and on honest is 0.0.
4. The L3 cell on paired_pauli_X is 1.0.
5. zeros() includes the L1/paired_pauli_X cell.
6. to_markdown() contains every attack name and every layer name, and every cell string
   contains both a bracketed interval and "n=".
7. There is NO function or attribute anywhere in the module named "accuracy".
8. false_positive_curve returns one entry per noise level, and the honest L1 FPR stays at
   or below a small bound at every level.
"""

from __future__ import annotations

import pytest

import pauliguard.evaluation as evaluation_module
from pauliguard.evaluation import (
    AttackOutcome,
    CellResult,
    EvaluationMatrix,
    evaluate,
    false_positive_curve,
)


@pytest.fixture(scope="module")
def eval_matrix() -> EvaluationMatrix:
    """Fixture providing an evaluation matrix evaluated at trials=60."""
    return evaluate(spec_name="lu-2022", trials=60, noise_p=0.0, alpha=1e-10, seed=42)


def test_1_evaluate_matrix_bounds_and_intervals(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 1: evaluate() at trials=60 returns a matrix whose every cell has

    trials>0 and 0<=rate<=1, and whose ci_low <= rate <= ci_high.
    """
    assert len(eval_matrix.cells) == len(eval_matrix.rows) * len(eval_matrix.cols)

    for (attack, layer), cell in eval_matrix.cells.items():
        assert isinstance(cell, CellResult)
        assert cell.trials == 60, f"Expected trials=60, got {cell.trials} for ({attack}, {layer})"
        assert 0.0 <= cell.rate <= 1.0, f"Rate {cell.rate} not in [0, 1] for ({attack}, {layer})"
        assert 0.0 <= cell.ci_low <= 1.0
        assert 0.0 <= cell.ci_high <= 1.0
        assert cell.ci_low <= cell.rate <= cell.ci_high, (
            f"Rate {cell.rate} outside CI [{cell.ci_low}, {cell.ci_high}] for ({attack}, {layer})"
        )


def test_2_l1_paired_pauli_zero_and_intercept_resend_one(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 2: The L1 cell on paired_pauli_X is EXACTLY 0.0 and the L1 cell

    on intercept_resend is EXACTLY 1.0.
    """
    l1_paired_x = eval_matrix.get_cell("paired_pauli_X", "L1")
    assert l1_paired_x.rate == 0.0, (
        f"L1 detection rate on paired_pauli_X must be EXACTLY 0.0, got {l1_paired_x.rate}"
    )

    l1_intercept_resend = eval_matrix.get_cell("intercept_resend", "L1")
    assert l1_intercept_resend.rate == 1.0, (
        f"L1 detection rate on intercept_resend must be EXACTLY 1.0, got {l1_intercept_resend.rate}"
    )


def test_3_l0_replay_one_and_honest_zero(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 3: The L0 cell on replay is 1.0 and on honest is 0.0."""
    l0_replay = eval_matrix.get_cell("replay", "L0")
    assert l0_replay.rate == 1.0, (
        f"L0 detection rate on replay must be EXACTLY 1.0, got {l0_replay.rate}"
    )

    l0_honest = eval_matrix.get_cell("honest", "L0")
    assert l0_honest.rate == 0.0, (
        f"L0 false positive rate on honest must be EXACTLY 0.0, got {l0_honest.rate}"
    )


def test_4_l3_paired_pauli_one(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 4: The L3 cell on paired_pauli_X is 1.0."""
    l3_paired_x = eval_matrix.get_cell("paired_pauli_X", "L3")
    assert l3_paired_x.rate == 1.0, (
        f"L3 detection rate on paired_pauli_X must be EXACTLY 1.0, got {l3_paired_x.rate}"
    )


def test_5_zeros_includes_l1_paired_pauli_x(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 5: zeros() includes the L1/paired_pauli_X cell."""
    zero_cells = eval_matrix.zeros()
    assert len(zero_cells) > 0, "zeros() returned empty list"

    has_l1_paired_x = any(
        c.layer == "L1" and c.attack == "paired_pauli_X" and c.rate == 0.0
        for c in zero_cells
    )
    assert has_l1_paired_x, "zeros() did not include the L1/paired_pauli_X cell"


def test_6_to_markdown_formatting_and_contents(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 6: to_markdown() contains every attack name and every layer name,

    and every cell string contains both a bracketed interval and "n=", and includes "DEFEATED BY PROTOCOL".
    """
    md = eval_matrix.to_markdown()

    # Must contain "DEFEATED BY PROTOCOL" for defeated attacks (e.g. unpaired_pauli)
    assert "DEFEATED BY PROTOCOL" in md

    # Every attack name in rows must be present in markdown
    for attack in eval_matrix.rows:
        assert attack in md, f"Attack name '{attack}' missing from to_markdown() output"

    # Every layer name in cols must be present in markdown
    for layer in eval_matrix.cols:
        assert layer in md, f"Layer name '{layer}' missing from to_markdown() output"

    # Every cell string must contain bracketed interval and 'n='
    for cell in eval_matrix.cells.values():
        formatted_str = cell.formatted()
        assert "[" in formatted_str and "]" in formatted_str, (
            f"Cell formatted string '{formatted_str}' missing bracketed interval"
        )
        assert "n=" in formatted_str, (
            f"Cell formatted string '{formatted_str}' missing 'n='"
        )
        assert formatted_str in md, (
            f"Formatted cell string '{formatted_str}' missing from to_markdown() output"
        )


def test_7_no_accuracy_in_module() -> None:
    """Assertion 7: There is NO function or attribute anywhere in the module named 'accuracy'.

    Non-negotiable rule: single aggregate accuracy numbers on imbalanced distributions are
    meaningless and strictly forbidden.
    """
    module_attrs = dir(evaluation_module)
    for attr in module_attrs:
        assert "accuracy" not in attr.lower(), (
            f"Forbidden identifier '{attr}' containing 'accuracy' found in evaluation module"
        )

    # Also check CellResult, AttackOutcome, and EvaluationMatrix attributes
    for attr in dir(CellResult):
        assert "accuracy" not in attr.lower(), (
            f"Forbidden identifier '{attr}' containing 'accuracy' found in CellResult"
        )

    for attr in dir(AttackOutcome):
        assert "accuracy" not in attr.lower(), (
            f"Forbidden identifier '{attr}' containing 'accuracy' found in AttackOutcome"
        )

    for attr in dir(EvaluationMatrix):
        assert "accuracy" not in attr.lower(), (
            f"Forbidden identifier '{attr}' containing 'accuracy' found in EvaluationMatrix"
        )


def test_8_false_positive_curve_properties() -> None:
    """Assertion 8: false_positive_curve returns one entry per noise level, and

    the honest L1 FPR stays at or below a small bound at every level.
    """
    noise_levels = (0.0, 0.001, 0.01, 0.05)
    curve = false_positive_curve(
        spec_name="lu-2022",
        noise_levels=noise_levels,
        trials=50,
        alpha=1e-10,
        decoy_rounds=400,
        seed=123,
    )

    # Returns one entry per noise level
    assert len(curve) == len(noise_levels)
    for p in noise_levels:
        assert p in curve, f"Noise level {p} missing from false_positive_curve output"
        layer_results = curve[p]
        assert "L0" in layer_results
        assert "L1" in layer_results
        assert "L2" in layer_results
        assert "L3" in layer_results
        assert "ANY" in layer_results

        # The honest L1 FPR stays at or below a small bound (<= 0.05) at every level
        l1_cell = layer_results["L1"]
        assert l1_cell.rate <= 0.05, (
            f"Honest L1 FPR {l1_cell.rate} at noise_p={p} exceeded bound 0.05"
        )
        assert l1_cell.ci_low <= l1_cell.rate <= l1_cell.ci_high


def test_9_attack_outcomes(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 9: Attack outcomes correctly track forgery success vs protocol defeat."""
    outcomes = eval_matrix.outcomes
    assert "paired_pauli_X" in outcomes
    assert "unpaired_pauli" in outcomes
    assert "honest" in outcomes

    paired_x = outcomes["paired_pauli_X"]
    assert paired_x.forgery_succeeded == 60
    assert paired_x.success_rate == 1.0
    assert paired_x.defeated_by_protocol is False

    unpaired = outcomes["unpaired_pauli"]
    assert unpaired.forgery_succeeded == 0
    assert unpaired.defeated_by_protocol is True

    honest = outcomes["honest"]
    assert honest.forgery_succeeded == 0


def test_10_structural_blindness_reporting(eval_matrix: EvaluationMatrix) -> None:
    """Assertion 10: structural_blindness() reports only genuine headline cases (paired_pauli) and never defeated attacks (unpaired_pauli)."""
    sb_lines = eval_matrix.structural_blindness()
    assert len(sb_lines) > 0

    # Must contain a line mentioning paired_pauli and L1
    has_paired_l1 = any("paired_pauli" in line and "L1" in line for line in sb_lines)
    assert has_paired_l1, f"Expected structural_blindness() to mention paired_pauli and L1, got {sb_lines}"

    # Must contain NO line mentioning unpaired_pauli
    has_unpaired = any("unpaired_pauli" in line for line in sb_lines)
    assert not has_unpaired, f"structural_blindness() must NOT mention unpaired_pauli, got {sb_lines}"
