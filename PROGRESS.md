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

## SCALING FINDING (2026-08-31) — our own result, NOT a reproduction
Permuted chained-CNOT (X/Z layer + CNOT chain + qubit permutation), full keyspace 4^n * n!
enumerated exactly. Adversary must FIX U in advance, so success = fraction of surviving keys.
RESULT: exactly TWO weight-1 attacks survive - Z on qubit 0 (chain head) and X on qubit n-1
(chain tail) - each at rate EXACTLY 1/n (1/2, 1/3, 1/4; rate*n = 1.0000, zero fit error).
MECHANISM: the CNOT chain propagates X forward and Z backward, so only the head/tail operators
do not spread. The residual 1/n is the chance the random permutation returns the attacked qubit
to the assumed position. Chaining alone does NOT stop the attack; it makes it POSITIONAL. The
permutation is what turns probability 1 into probability 1/n.
Only X-on-tail changes a computational-basis message; Z-on-head is a phase flip and must not be
counted as a forgery.
HONESTY: the secondhand figure is 1/(8n); we measured 1/n. Ratio exactly 8 = 2^3, consistent
with three further single-bit key conditions in their construction that ours does not model.
WE DO NOT CLAIM REPRODUCTION. We did not tune to hit 1/(8n). Closing this properly requires
arXiv:2603.19985 (~1h once in hand) and would upgrade it to genuine external validation.
Written up in docs/scaling_finding.md.

## LIVE SPEC EDITING — COMPLETE (2026-08-31)
The unrehearsed-input demo. Judge edits YAML in the browser; nothing is written to disk.
POST /api/analyse_spec parses a raw YAML string, runs validate_spec, L3, DisputeAnalyser and
short honest/attacked batches, and returns dimension, certificates, dispute findings and rates.
Browser-verified end to end (clicked the actual buttons):
  baseline lu-2022        dim=4 certs=1 forgery=1.0000 honest=1.0000
  + swap_test copies=8    dim=4 certs=0 forgery=0.0000 honest=1.0000   <- attack disappears
  - arbitrator check      dim=4 certs=1 forgery=1.0000 honest=1.0000
  malformed YAML          HTTP 400 stage=parse (never 500, never a blank screen)
  unknown encryption      parsed_ok with a warning, not a crash
NOTE, state it if asked: removing the arbitrator check does NOT grow the malleability dimension,
because at n=2 dim is already 4 = 2n, i.e. the whole Pauli group modulo phase. It is maximal and
cannot grow. That is correct behaviour, not a bug.

## SIH IDEA DECK — BUILT (2026-08-31)
`deck/SIH26141_PauliGuard_Idea_Submission.pptx` (+ .pdf render), built from the OFFICIAL
template at ~/Downloads/SIH2026-IDEA-Presentation-Format.pptx by `tools/build_deck.py`
(re-runnable). 6 slides incl. title; template's instruction slide 7 deleted; section headings
NEVER renamed (they are the scoring rubric).
Follows ~/Claude/hackathon-decks/PHILOSOPHY.md: read-deck density, boxes not bullets,
architecture diagram on slide 3, every benefit claim numbered + sourced, ONE figure enormous
(0.000 at 72pt), named risks paired 1:1 with specific mitigations, team pill same position,
references with DOIs, real UI screenshot (tools/capture_ui.py, re-runnable).
OPEN ITEMS THE USER MUST RESOLVE BEFORE SUBMITTING:
  1. Team ID and Team Name are placeholders "<your team ID>" / "<registered team name>".
     A mismatch against the portal record is an unforced error.
  2. THE GITHUB REPO IS PRIVATE. The slide-6 "PROOF OF LIFE" link is dead for a judge.
     Make it public before submission or replace the link.
  3. Density is 430 words/slide vs the corpus winner median of 131.8. Deliberate (read deck),
     but slide 4 at 626 words is the outlier and is the one to trim if trimming.
  4. Body text runs 8.6-9pt in places, below the 10pt floor PHILOSOPHY.md recommends.

## DEPLOYMENT — BOTH LIVE (2026-09-01)
Split hosting, both green:
  • Frontend  https://pauliguard-v2.vercel.app        (Vercel, static `web/`)
  • Backend   https://pauliguard-v2-api.onrender.com  (Render Docker free, stim+FastAPI)
The Vercel page reads "Backend Online" and pulls schemes/floor/runs from Render directly
over CORS (`allow_origins=["*"]`), NOT via Vercel rewrites. `web/app.js` picks the target:
`?api=` param > `window.PAULIGUARD_API_BASE` > localStorage > if hostname contains
`vercel.app` use the Render URL > else same-origin. Same-origin is what makes
https://pauliguard-v2-api.onrender.com/ work standalone as a full demo URL too.

### The Vercel bug, and what it actually was
Every deployment sat at CLI status `UNKNOWN` forever — CLI deploys included. This was
misread for hours as a wedged build queue or as Vercel auto-detecting `pauliguard/api.py`
as a FastAPI project and failing on the stim C++ wheel.

Neither. `GET /v6/deployments` reported the real state, which the CLI does not surface:

    "state": "BLOCKED",
    "seatBlock": { "blockCode": "COMMIT_AUTHOR_REQUIRED" },
    "errorMessage": "The Deployment was blocked because GitHub could not
                     associate the committer with a GitHub user."

This repo had NO git identity configured (neither local nor global), so git derived one
from the hostname: `harshwardhan@harshwardhans-MacBook-Air.local`. That address belongs to
no GitHub account, so Vercel's seat attribution refused to bill the build to anyone and
blocked it pre-build. Duration `?`, `Builds [0ms]`, `vercel logs` empty — because no build
ever started. CLI deploys were blocked identically (`"no git user associated with the
commit"`) since the CLI attaches local commit metadata.

Fix (48ac2b0): set the repo-local identity to the GitHub account's own address, then push.

    git config user.name  "harshwardhan-kp"
    git config user.email "harshw.kp@gmail.com"

Next push deployed READY in 2s. All three aliases now resolve to it.

DIAGNOSTIC LESSON: `vercel ls` renders a BLOCKED deployment as `UNKNOWN`. When a deploy
hangs with no logs and no build duration, query the REST API before touching config —
`framework: null`, `.vercelignore`, and the deleted/recreated project were all fixes for a
problem that did not exist. They are harmless and are kept, but they were not the bug.

### Config that must stay
  • `vercel.json` — `{"outputDirectory":"web","cleanUrls":true,"framework":null}`.
    `framework:null` still earns its place: without it Vercel detects `pauliguard/api.py`
    (`variable: app`) as FastAPI and tries a Python build that stim will fail.
  • `.vercelignore` — hides `pauliguard`, `render.yaml` is NOT ignored... see below.
  • `render.yaml` — required by the Render blueprint, and it must stay hidden from Vercel
    or Vercel's services detection errors with "Invalid vercel.json services pattern".
  • SSO/deployment protection is DISABLED on the project. Re-enabling it 302s judges to a
    vercel.com login. `vercel project protection disable pauliguard-v2 --sso`.

### Still open
  1. Git identity is REPO-LOCAL only. Any other repo on this machine will hit the same
     Vercel block. `git config --global user.email harshw.kp@gmail.com` to fix machine-wide.
  2. Render autoDeploy needs the owner to Connect GitHub once in the Render dashboard
     (OAuth). Until then the API alone returns "repository URL is invalid".
  3. REVOKE the Render API key `rnd_pSJm...` (Dashboard -> Account -> API Keys) — it was
     used in plaintext during setup.
  4. `/favicon.ico` 404s on the deployed page. Only console error; cosmetic.
  5. Render free tier cold-starts (~50s) after 15 min idle. Warm it before judging.

## 2026-09-04 — Judge-mode UI rebuild (dossier) + expert console split
Supervisor: Muse Code (Muse Spark). Workers: `agy` + `agy2` (gemini-3.8-flash-high)
for bulk files; typography/grounds re-theme done directly by supervisor per user order.

**Why:** the single-page console (6 knobs + YAML + L0-L3 math at once) drowned
non-quantum judges. New structure, same backend, zero backend changes:
  • `web/index.html|styles.css|app.js` REWRITTEN — threat-dossier landing for judges:
    hero verdict, score strip, Exhibit A/B lockstep, cross-examination rows with
    `why` derivations, replay (scheme cards + n stepper + advanced details),
    methodology footer with verbatim sound-not-complete line, amber OFFLINE
    PREVIEW state with [CACHED EXAMPLE] tags when backend unreachable.
  • `web/console.html|console.js|console.css` NEW — byte-identical expert console
    from git HEAD (`console.js` verified `cmp`-clean vs old `app.js`), linked as
    [CONSOLE]. Old YAML editing / mutate buttons / derivations live on here only.
  • `web/fonts/` NEW — self-hosted OFL faces, no CDN: Instrument Serif 400+italic,
    Schibsted Grotesk (variable 400-700 latin). Design tokens + palette + ink-only
    verdict doctrine taken from `~/Claude/grounds/src/app/globals.css` (ground
    #eeeeee, ink #000, red #e10909 reserved for defects; green removed from all
    verdict paths, kept nowhere — online dot is ink too).
  • Broke stale hard links: `web/{index.html,styles.css,app.js}` were hardlinked
    into `.vercel/output/static/` (local build cache). `cp`+`mv` re-inoded the
    working files; bytes unchanged. `.vercelignore` does not exclude `web/fonts`,
    so faces deploy.

**Verified (this session, independent of workers):** `node --check` both JS files;
40/40 `getElementById` refs resolve in new HTML; live-backend contract check
(`TestClient`: compare honest [0,1]->[0,1] intact / forged [0,1]->[1,1] accepted+
changed, L0-L2 clear, L3 +XI dim4 1.0 16/16); Playwright (Chromium) full pass —
auto-compare verdict, replay at n=3, offline preview, console page, zero JS
errors; screenshots inspected pixel-level. `git status` scope: only the 3
rewrites + console.* + fonts/ + this entry. Nothing committed until user said push.

## 2026-09-04 (pm) — honest-run 422 + [object Object] banner (fixed, pushed)
Symptom (prod + localhost): clicking Run honest showed
`Honest run failed: [object Object]`. Root causes, both frontend in
`web/app.js`: (1) honest payload sent `attack_pauli: null`, but `RunRequest`
declares `attack_pauli: str` (not Optional) → FastAPI 422; compare path always
sent `state.attack_pauli`, which is why only honest broke. (2) error formatter
interpolated `errJson.detail` raw; 422 bodies carry it as an object/array.
Fix: send `state.attack_pauli || "X"`; new `httpError(res)` helper stringifies
non-string details; both `res.ok` branches use it. Backend untouched (verified
`attack: null` returns 200 with `{layers, summary, trace}`). Playwright now
clicks Run honest and asserts the honest verdict + no banner; full suite green,
zero JS errors.
