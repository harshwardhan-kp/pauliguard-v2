# PauliGuard v2 — instructions for any agent working here

Read `PROGRESS.md` first. It is the source of truth.

## Environment
Always use `.venv/bin/python` (3.12.14). System python is 3.14 and has no qiskit wheels.
Run tests with `.venv/bin/python -m pytest -q`.

## Hard rules (violating any of these is a defect, not a style choice)
1. **No numeric threshold literals.** Every threshold derives at runtime from a declared
   security parameter, the calibrated floor, and the sample size, via a named inequality.
   Store the derivation so the UI can display it.
2. **Serfling, not Hoeffding**, for decoy statistics — sampling is without replacement.
3. **No AI/ML in the detection path.** No sklearn, no torch, no fitted thresholds.
4. **L3 is sound, not complete.** Never write a docstring or doc claiming it proves security.
5. **τ is floor-relative**, never absolute: flag iff (x̄ − floor) ≥ τ.
6. Every claim in a docstring must be backed by a test.

## Style
Plain, dependency-light Python. Type hints. Dataclasses over dicts for structured data.
Docstrings state what is PROVEN and what is ASSUMED, separately.
