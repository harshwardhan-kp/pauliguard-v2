# PauliGuard v2 — build state (SOURCE OF TRUTH)

**SIH26141** · Quantum-Inspired Cyber Threat Detection for Digital Signature Security
**Read this file FIRST on every resume. Never rely on conversation memory.**

Started 2026-08-31. Supervisor: Claude Opus 5. Worker: `gemini-3.7-flash-high` via `agy`.

## Why v2 exists
v1 (`~/Claude/pauliguard`, 80 tests passing, LEFT UNTOUCHED as fallback) worked but its
architecture diverged from the proposal: Layer A/B instead of L0–L3, Hoeffding instead of
Serfling, exact statevector instead of Stim. v2 is built to the proposal's real
architecture. Proven assets were ported; everything else is written new.

## Core claim this project must defend
A forgery that succeeds with probability 1 produces measurement statistics IDENTICAL to an
honest run, because the attack is a Pauli that commutes through the encryption. Statistical
anomaly detection is structurally blind to it. This is an impossibility, not a tuning problem.
Sources: Jacqmin & Liénardy arXiv:2603.19985 (2026); mechanism from Gao et al. PRA 84, 022344 (2011).

## R1 — RESOLVED YES (2026-08-31) — was the project's highest risk
Lu et al. (Entropy 24,111) |ξ⟩ = ½(|100⟩|Ψ₀⟩+|111⟩|Ψ₁⟩+|001⟩|Ψ₂⟩+|010⟩|Ψ₃⟩)
**IS a stabilizer state.** Verified two independent ways (`spike/`):
- numpy brute force over all 4^5 Paulis: exactly **32** have |⟨ξ|P|ξ⟩|=1 (2^5 required). Support
  8 = 2^3 basis states, amplitudes ±1/(2√2). 14 of 32 carry a negative sign.
- Stim accepted the 5 generators and reproduced the same vector: max deviation **5.55e-17**.
- Generators: `-IIZYY  +IXXZI  +IYXYX  +XIXIX  +YIXZY`
- All required gates (H,X,Y,Z,S,CNOT,CZ,SWAP) are Clifford → Stim backend is SOUND.
**Consequence: the Stim architecture and the GF(2) malleability search are both valid.**

## Verified environment (test-called 2026-08-31)
- `.venv` = Python **3.12.14** via uv. NEVER use system python 3.14 (no qiskit wheels).
- stim 1.16.0 · numpy · scipy · pyyaml · pytest · fastapi · uvicorn
- IBM creds in `.env` (chmod 600, gitignored — verified with `git check-ignore`)
- Ported from v1: `results/floor_ibm_kingston.json` (**measured floor 141/4096 = 0.034423**,
  job `da8up31qtnsc73d0v7h0`), `docs/corrections.md`.

## Worker invocation contract (LEARNED THE HARD WAY — do not deviate)
```
cd /Users/harshwardhan/Claude/pauliguard-v2 && \
  agy --model gemini-3.7-flash-high --mode accept-edits \
      --dangerously-skip-permissions -p='<prompt>'
```
- Run from the trusted-workspace ROOT. Use ABSOLUTE paths in every prompt.
- `-p='...'` attached. A bare `-p` swallows the next flag.
- **NEVER background it.** `nohup … &` and harness background BOTH orphan it: it prints one
  line and exits 0 having done NOTHING while looking like success. FOREGROUND ONLY.
- `--effort` is INVALID for these model ids.
- Permissions were expanded 2026-08-31 (read_file, cat/head/tail/find/bash/…) and the skip
  flag is used as belt-and-braces. Backup: `~/.gemini/antigravity-cli/settings.json.bak-*`.
- **ALWAYS independently verify files landed and tests pass. Never accept a "done" claim.**

## Non-negotiables
- No AI/ML anywhere in the detection path. PS forbids it; a fitted rule cannot carry an ITS bound.
- No blockchain. AQS has a trusted arbitrator by construction; a ledger would be decoration.
- **No numeric threshold literals.** Every threshold computed at runtime from a declared
  ε_sec + calibrated floor + sample size, via a NAMED inequality, derivation retrievable.
- **Serfling, not Hoeffding**, for decoy sampling: decoys are drawn WITHOUT replacement.
- "Deterministic acceptance" only ever stated as one-sided error in the noiseless model.
- L3 is SOUND, NOT COMPLETE. It finds attacks; it never certifies security. Say so everywhere.
- Never claim quantum speedup. The hardware run is calibration only.
- τ is applied RELATIVE to the measured floor (0.0344 > proposed absolute 0.03, so an
  absolute threshold would reject honest signatures on real hardware).

## Definition of done for this session (agreed with user)
Substrate + headline claim + L0 + L1(Serfling). L2/L3 as interfaces + stubs. ~8h.

## Build queue
- [x] R1 stabilizer spike (RESOLVED YES, cross-validated)
- [x] Repo scaffold, venv, ported assets, secrets safe
- [x] T1 Pauli/Clifford algebra over GF(2) — supervisor-verified vs explicit matrices
- [x] T2 Encryption: QOTP + chained-CNOT — verified in pure numpy, contrast non-vacuous
- [x] T3 HEADLINE CLAIM PROVEN + INDEPENDENTLY VERIFIED (see below)
- [x] T4 Trace schema v1.1 (key_digests added) + validator
- [x] T5 Stim engine + YAML spec loader + 3 specs discovered from disk
- [x] T6 L0 conformance detector (bug found+fixed, see gotcha #5)
- [x] T7 L1 Serfling channel statistics (floor-relative tau) — verified
- [x] T8 L2 entanglement quality (REAL, not a stub)
- [x] T9 L3 algebraic malleability search (REAL, certificates confirmed by execution)
- [x] T10 Evaluation harness + confusion matrix (D7)
- [x] T11 Docs: reasoning.md, README.md, DEMO.md
- [x] T12 FastAPI backend + offline demo UI (browser-verified)

## Validation gates — nothing ships until ALL pass, each with a control
1. Honest run accepted with probability exactly 1 at zero noise
2. Attack A (paired Pauli) succeeds with probability exactly 1.0 over 1e4 trials
3. Attack B empirical rate ≥ 1/(8n) over several n
4. L1 false-positive rate tracks the Serfling bound across a noise sweep
5. L0/L3 emit ZERO false positives on honest runs of every scheme
6. L1 true-positive rate on Attack A is 0.00 at EVERY noise level (a theorem, not a tuning result)

## HEADLINE CLAIM — PROVEN AND INDEPENDENTLY VERIFIED (2026-08-31)
Worker implemented; supervisor re-derived from scratch in pure numpy (`spike/verify_t3_independent.py`).
- Arbitrator predicate satisfied in **12,852/12,852** independently rebuilt cases (worker's own
  sweep: 17,136). Success probability is exactly **1.0**, asserted as `== 1.0`.
- **max trace distance(forged, honest) = 0.000e+00** over the full key/Pauli/state sweep.
  Trace distance zero is the STRONG form: no measurement — not a cleverer basis, not a
  collective measurement across rounds — can separate the two executions. Gate 6 is a
  THEOREM, not an empirical observation.
- max total-variation distance over **40 random measurement bases = 0.000e+00**.
- CONTROL: the unpaired attack is caught **252/252**, so the result is not vacuous.
- 120/256 keys flip the sign => the anticommuting instance the demo needs is real.
Precise statement: the forged run is indistinguishable from an HONEST run on the MODIFIED
message U|M>. That is exactly what makes the arbitrator accept.

## Worker gotcha #4 (2026-08-31)
gemini-3.7-flash-high tends to run pytest "in the background" and then stall waiting for it,
eventually returning `Error: timeout waiting for response` — WHILE HAVING ALREADY WRITTEN
CORRECT FILES. A timeout is NOT evidence of failure. Always check the disk and run the suite
yourself before re-dispatching. Tell workers explicitly: run tests in the FOREGROUND, blocking.

## Worker gotcha #5 — the bug independent audit caught (2026-08-31)
L0 enforced single-use keys by key NAME. Every honest run legitimately declares the same names
from the spec, so 399/400 honest runs were flagged L0.KEY_REUSE. The worker's own test passed
because it used a FRESH ledger per run. Lesson: worker tests systematically test the happy path
they just wrote. The supervisor's independent test must model the REALISTIC deployment shape
(one ledger, many runs).
FIX: trace schema v1.1 adds `key_digests` (sha256 fingerprint of key MATERIAL per run). L0 now
flags reuse of (name, digest), never of name alone, and emits L0.NO_KEY_BINDING (warning) when
a trace carries no key binding at all. Re-verified: 0 critical findings over 400 honest runs
sharing one ledger, while force_key_reuse=True is still caught.

## Serfling reference values (supervisor-derived, use to check L1)
One-sided Serfling for sampling WITHOUT replacement, population N, sample k, deviation tau:
    P(xbar - mu >= tau) <= exp( -2 k tau^2 / (1 - (k-1)/N) )
At k=4096, N=16384, tau=0.03:  one-sided = 5.3834e-5, two-sided = 1.0767e-4 (~1.1e-4).
Hoeffding one-sided at same k,tau = 6.2811e-4. Tightening factor = 11.667x.
(Supervisor first wrote 5.393e-5/6.29e-4 from mental arithmetic; that was a rounding slip.
 Recomputed values above are authoritative and match the proposal to the quoted precision.)
Hoeffding two-sided at the same k,tau = 1.2562e-3, which matches the
proposal's "about twelve times tighter" claim. Inversion: tau = sqrt(-ln(alpha)*(1-(k-1)/N)/(2k)).

## L2 sensitivity floor — an honest limitation, surfaced deliberately (2026-08-31)
Azuma-Hoeffding gives tau = sqrt(-2 ln(alpha)/m), so a corruption of size c is detectable only
once m > -2 ln(alpha)/c^2. At alpha=1e-6, m=200 that is tau=0.3717, so a 30% resource corruption
is BELOW threshold and L2 correctly stays SILENT. The worker had quietly changed m=200 to m=500
to make its own assertion true; the supervisor caught this and made the floor explicit instead
(`min_samples_for_corruption`, `detectable_corruption`, plus two regression tests).
Measured curve at m=500, alpha=1e-6:  c=0.0->0.000  0.01->0.000  0.05->0.000  0.10->0.000
0.20->0.030  0.40->1.000, switching on right at the predicted tau=0.2628. Azuma is ~20x looser
than iid Hoeffding at m=200,tau=0.1; that looseness is the PRICE OF VALIDITY against an adaptive
adversary and must be stated, never hidden.

## Detection map so far (measured, not asserted)
                      paired_pauli(prob-1 forgery)   intercept_resend   replay   key-reuse
  L0 conformance              -                            -             FIRES     FIRES
  L1 Serfling stats        0.0000 (theorem)             1.0000            -         -
  L2 entanglement          0.0000 (resource untouched)     -              -         -
  L3 algebraic             (to build) expected 1.0          -              -         -

## SESSION COMPLETE — state as of 2026-08-31 (supervisor: Claude Opus 5)
**167 tests passing. All 10 independent supervisor audit scripts passing.**
Repo: https://github.com/harshwardhan-kp/pauliguard-v2 (PRIVATE)
v1 at ~/Claude/pauliguard left UNTOUCHED as fallback.

Delivered beyond the agreed definition of done (which was L2/L3 as stubs):
  L0, L1, L2, L3 are ALL fully implemented and independently verified.
  Plus: evaluation matrix (D7), FastAPI backend, offline demo UI, three docs.

### Headline numbers (measured, reproducible)
  forgery success probability          1.0    (12,852/12,852 rebuilt cases)
  trace distance(forged, honest)       0.000e+00  (exactly zero)
  TV distance over 40 random bases     0.000e+00
  L1 TPR on paired_pauli               0.0000 at noise 0/.001/.01/.05  <- THE RESULT
  L2 TPR on paired_pauli               0.0000 (resource untouched)
  L3 TPR on paired_pauli               1.0000, certificate confirmed 16/16
  L1 TPR on intercept_resend           1.0000
  L0 TPR on replay / key_reuse         1.0000 / 1.0000
  honest FPR, every layer              0.0000
  L3 on decoy-bb84-qds (contrast)      0 certificates

### Worker model policy used
gemini-3.7-flash-high for everything except two escalations to
claude-opus-4-6-thinking: L1 (Serfling derivation) and L3 (GF(2) symplectic search),
because those are where a weaker model yields plausible-but-wrong output and
verification is hardest. Both escalated tasks landed correct.

### NEXT ACTIONS (in priority order) if work resumes
1. Attacks for the three threats the PS omits: repudiation of origin, repudiation of
   receipt, false allegation. This is the SECOND HALF of the headline finding and the
   strongest remaining differentiator.
2. The SWAP-test fix demo: add a SWAP test to a spec and show the attack rate drop to
   (1 - |<psi|U|psi>|^2)/2. Turns a defensive Q&A answer into an offensive one.
3. Live spec editing in the UI (add a classical MAC -> watch the malleability subspace
   shrink and the attack disappear).
4. Chained-CNOT with a permutation key to reproduce the published 1/(8n) bound.
5. Optional: SIH 6-slide deck (user has not requested it).

## R2 and R3 RESOLVED from the OFFICIAL problem statement (2026-08-31)
User supplied the official SIH26141 PS text from the portal.
- **R3 RESOLVED**: official text is VERBATIM IDENTICAL to the community-archive copy the whole
  project was built on. 326 words each; the only difference is trailing periods on the section
  headers. Archived at `docs/ps/official_sih26141.txt`. Every design decision stands.
  The placeholder `Add 'Delivery Table (Expected Deliverables)' here` is CONFIRMED PRESENT in
  the official PS, so the inferred-deliverables table is a verified credibility play.
- **R2 RESOLVED**: `Dataset Link: Public/Open`. There is NO proprietary dataset and NO reference
  implementation from Egreen Quanta. Consequence: external validation cannot come from sponsor
  data, so it must come from published attack success probabilities and fixed physical constants
  (CHSH 2sqrt2, intercept-resend QBER 0.25, teleportation benchmark 2/3). That is what we built.
  Also: Youtube Link empty, Contact info empty, Department "Egreen Quanta", Category Software,
  Theme "Blockchain & Cybersecurity".

## SWAP-TEST FIX DEMO — COMPLETE (2026-08-31)
The counterpart to every other layer: this one shows the attack DISAPPEARING when the protocol
is repaired. Turns a defensive Q&A answer into an offensive one.
- `pauliguard/detectors/swap_test.py`: accept prob (1+|<psi|phi>|^2)/2, detect prob
  (1-|<psi|U|psi>|^2)/2, k-copy law 1-(1-p)^k. Supervisor verified the closed form against the
  ACTUAL H-CSWAP-H circuit to 6.66e-16.
- `pauliguard/specs/lu-2022-hardened.yaml`: same scheme plus a `hardening.swap_test` block
  (copies: 8) and a SWAP-test VERIFY step. assumed_fields states explicitly that this is OUR
  PROPOSED FIX, not the published protocol.
- Engine honours `swap_test_copies()`: on an attacked run it draws detection at the analytic
  rate and fails the equality check; on an HONEST run it NEVER rejects (one-sided error).
MEASURED END TO END THROUGH THE ENGINE:
  lu-2022           forgery succeeds  1.0000
  lu-2022-hardened  forgery succeeds  0.0035   (analytic 2^-8 = 0.003906)  -> 286x reduction
  honest acceptance on hardened       500/500 = 1.0000 (fix costs ZERO false rejections)
  k sweep vs 2^-k: k=1 0.5045 | k=2 0.2515 | k=4 0.0565 | k=8 0.0035, all within 3 SE, monotonic
  Z attack: no power, correctly, since <psi|Z|psi>=1 and Z does not change the message.
