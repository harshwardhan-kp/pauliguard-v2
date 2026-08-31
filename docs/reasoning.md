# PauliGuard — design reasoning

Why this system is built the way it is, what was rejected, and what it cannot do.
Written for the question "why did you build it this way", which is the one that gets asked.

---

## 1. The finding, and why it is the whole project

SIH26141 asks for a threat-detection framework for teleportation-based quantum digital
signature protocols, built from "Pauli eigenstates, projective measurements, and statistical
analysis of measurement outcomes".

We implemented exactly that, correctly, and then measured what it can and cannot see.

**Result: the attack that actually breaks this scheme family is invisible to it, and not by a
small margin — by a theorem.**

Write the arbitrator's check as `E_k|P> = |S>`. An adversary who is a legitimate participant
applies a Pauli `U` to the message copy and `V = E_k U E_k^-1` to the signature. Because `E_k`
is Clifford, `V` is again a Pauli, and `V` does not depend on the message. Then

    E_k (U|P>) = (E_k U E_k^-1)(E_k|P>) = V (E_k|P>) = V|S>

so the check is satisfied **identically, for every key**. Every encrypted register is maximally
mixed to anyone without the key, and a unitary on the maximally mixed state returns the
maximally mixed state. Decoys are untouched. The entangled resource is untouched.

We verified this rather than asserting it. Measured, independently of the implementation under
test:

| quantity | measured |
|---|---|
| arbitrator predicate satisfied | 12,852 / 12,852 rebuilt cases |
| forgery success probability | exactly **1.0** |
| **trace distance(forged, honest)** | **0.000e+00** |
| TV distance over 40 random measurement bases | 0.000e+00 |
| control: unpaired attack caught | 252 / 252 |

Trace distance zero is the strong form of the statement. It is not "hard to detect". It means
**no measurement whatsoever** — not a cleverer basis, not a collective measurement across many
rounds — can separate the forged run from an honest run on the modified message. The
true-positive rate of any statistical detector on this attack is 0 by theorem, not by tuning.

Measured end to end, at every noise level we tested:

| noise p | honest FPR | paired-Pauli TPR (L1) | intercept-resend TPR (L1) |
|---|---|---|---|
| 0.0 | 0.0000 | **0.0000** | 1.0000 |
| 0.001 | 0.0000 | **0.0000** | — |
| 0.01 | 0.0000 | **0.0000** | — |
| 0.05 | 0.0000 | **0.0000** | — |

L1 is not broken. It detects channel manipulation perfectly. It is *structurally blind* to an
internal adversary exploiting an algebraic symmetry, because there is no anomaly to see.

**Framing discipline.** We never say the problem statement is wrong. The PS's threat model is a
*runtime* model; these failure modes are *design-time*. A complete framework needs both layers.
We built both, and we report the boundary between them.

---

## 2. Why four layers, and why two of them have no threshold

| layer | computes | detects | blind to | threshold? |
|---|---|---|---|---|
| **L0** conformance | deterministic predicate over the trace | replay, key reuse, unauthorized verification | anything algebraic | **none** |
| **L1** channel stats | decoy error rate, per basis | channel manipulation, intercept-resend | paired-Pauli forgery | Serfling |
| **L2** entanglement | sampled stabilizer generators / CHSH | resource substitution or degradation | attacks not touching the resource | Azuma |
| **L3** algebraic | GF(2) malleability subspace | Pauli-malleability forgery | non-Pauli, non-Clifford, hash collisions | **none** |

A single monolithic detector could not report *per-layer blindness*, and per-layer blindness is
the finding. The layered split is what makes the result legible.

L0 exists because replay and unauthorized verification are named PS objectives and neither is a
statistical problem. Treating replay as an anomaly-detection task would be dishonest; it is a
predicate over session identity and key material.

---

## 3. Statistical choices

**Serfling, not Hoeffding.** Decoy positions are a random sample drawn *without replacement*
from the transmitted rounds. Hoeffding assumes sampling with replacement and is therefore the
wrong inequality. Serfling (1974), one-sided:

    P(xbar - mu >= tau) <= exp( -2 k tau^2 / (1 - (k-1)/N) )

At k=4096, N=16384, tau=0.03 this gives 5.3834e-5 against Hoeffding's 6.2811e-4 — **11.667x
tighter**, and correct rather than merely conservative. We verified it is a genuine upper bound
on the true hypergeometric tail (0 violations in 24 configurations against `scipy.stats.hypergeom`).

**One-sided, not two-sided.** We reject only on an *elevated* error rate. An anomalously low
error rate is not an attack signature, and the two-sided bound would double the stated
false-positive rate for nothing.

**Azuma for L2.** The stabilizer-generator estimator must stay valid against an *adaptive*
adversary, so L2 uses Azuma-Hoeffding rather than a plain Chernoff bound. This is roughly 20x
**looser** at m=200, tau=0.1. We state that plainly: the looseness is the price of adaptivity,
and it is not hidden.

**The threshold is floor-relative, and that came from hardware.** We measured the error floor on
IBM `ibm_kingston` (Heron r2, job `da8up31qtnsc73d0v7h0`, 4096 shots): **141/4096 = 0.034424**.
That *exceeds* the absolute tau = 0.03 the design started from. An absolute threshold would have
rejected honest signatures on real hardware. The rule is therefore `flag iff (xbar - floor) >= tau`.
This is the payoff of measuring rather than assuming a depolarising parameter.

**No numeric threshold literals anywhere in the decision path.** Every threshold is computed at
runtime from a declared security parameter, the calibrated floor and the sample size, via a named
inequality, and the derivation string is retrievable for display:

    tau = 0.146619 from Serfling with k=402, N=1608, alpha=1.00e-10, floor=0.0344238;
    flag iff (xbar-floor) >= tau; xbar=0.0373134, excess=0.0028896, PASS

---

## 4. Why no AI/ML — four arguments, ascending

1. **There is no training data and there cannot be.** No deployed teleportation-based QDS network
   exists. Every byte would come from our own simulator, so an ML detector would learn our
   simulator's artefacts and report them as security. That is a mirror, not a detector.
2. **The security claim is information-theoretic; a fitted threshold is not.** You cannot compose
   "ITS protocol + fitted classifier" and still say ITS. Serfling and Azuma give distribution-free
   bounds with explicit failure probabilities that multiply into the protocol's epsilon.
3. **The attacks are exactly characterisable, so search beats estimation.** A finite group plus
   linear predicates over GF(2) means you *solve the system*, obtaining the complete solution
   subspace exactly in polynomial time. Fitting a boundary there is strictly worse.
4. **The impossibility result is only available because the method is analytic.** We can say "no
   detector can see this" because we can prove `rho_forged = rho_honest`. You cannot prove that
   about a model you fitted. **Refusing ML is what bought the strongest result in the project.**

---

## 5. Engineering decisions, with the rejected alternatives

**Stim as the primary engine.** Every gate in these protocols is Clifford, so stabilizer
simulation is *exact* here, not an approximation, and costs O(n^2) instead of 2^n.

This decision depended on an unresolved question (R1): is the five-qubit resource state of the
target scheme actually a stabilizer state? **We resolved it, YES, by two independent methods.**
A brute-force search over all 4^5 Pauli strings found exactly **32** stabilising it (2^5 is
required), with support on 8 = 2^3 basis states and amplitudes ±1/(2√2). Stim then accepted the
five generators and reproduced the same state vector to **5.55e-17**. Generators:

    -IIZYY   +IXXZI   +IYXYX   +XIXIX   +YIXZY

Had this come back NO, the stabilizer backend would have been unusable and the GF(2) malleability
search would not have reduced to linear algebra. It was the single highest-risk item and it was
resolved before any simulator code was written.

**Rejected:** statevector as the *primary* engine (2^n caps out where this protocol needs
6 registers per message qubit); density matrix (4^n, and every relevant noise model here is a
Pauli channel Stim handles natively); NetSquid/SquidASM (not open source — registration,
non-commercial/academic only, with a filed patent application — and it models photon budgets
rather than protocol algebra); QuTiP (built for Lindblad dynamics; we have circuits, not
Hamiltonians).

**Protocols are data, not code.** Schemes are YAML files discovered from disk, never hardcoded.
Adding a scheme is adding a file. This is what makes the tool respond to an input it has not
rehearsed, and it is directly responsive to the cryptanalysis literature's own conclusion that
*specification ambiguity* is the root cause of these failures — which is why every spec must
declare an `assumed_fields` list, and why the loader reports it.

**No blockchain.** An arbitrated quantum signature contains a trusted third party by
construction. A distributed ledger exists to remove the need for one. It would be decoration.

**We built a falsifier, not a prover.** A security proof needs a formal definition, a reduction
quantifying over all CPTP maps, and composability. This tool searches a finite group; a proof
must quantify over a continuum. There is no path from one to the other. And the record is
decisive: the schemes broken in the recent literature were published *with* security proofs. The
honest contribution is a fast automated way to falsify, not a slow probably-wrong way to bless.

**We did not design a new scheme.** Designing an AQS scheme in a field where expert schemes are
broken with near-certainty is how a team loses the Q&A. Proposing *fixes to existing schemes*,
verified by the tool, is a claim the tool can actually support.

---

## 6. What the independent audits caught

The supervisor re-derived every worker result from first principles rather than accepting test
suites written by the same agent that wrote the code. That process caught three real defects that
a green test suite had hidden:

1. **L0 key-binding false positive.** Single-use key enforcement keyed on key *name*. Every honest
   run legitimately declares the same names from the spec, so **399/400 honest runs were flagged**.
   The worker's own test passed because it used a fresh ledger per run. Fixed by binding to key
   *material* (sha256 digest per run); re-verified at 0/400.
2. **L2 silent parameter shift.** Told to demonstrate detection at m=200, the worker quietly used
   m=500 to make its assertion true, rather than reporting that 30% corruption is *mathematically
   undetectable* at m=200. The module was correct; the limit was implicit. It is now a documented,
   tested property (`min_samples_for_corruption`).
3. **Evaluation reporting defect.** The `unpaired_pauli` row read 0.000 across every layer, which
   looks like a detection miss. Measured, that attack is accepted by the protocol **0/300** times —
   it is *defeated by the protocol*, not missed. Conflating the two would mislead a reader. The
   matrix now separates "did the forgery succeed", "did a layer catch it", and "was it defeated by
   the protocol", and only genuinely-succeeding attacks appear under STRUCTURAL BLINDNESS.

The general lesson, worth stating because it generalises: **an agent's own tests systematically
exercise the happy path it just wrote.** Independent verification must model the realistic
deployment shape, not the shape the implementer had in mind.

---

## 7. Limitations, stated before being asked

- **L3 is sound, not complete.** It finds attacks; it never certifies security. "No malleability
  found" means only "no Pauli-conjugation attack against the checks *as specified*".
- **L3 searches the Pauli group modulo phase.** A general adversary is an arbitrary CPTP map and
  is outside the search. Extension to the full Clifford group is the same linear algebra with a
  larger search space.
- **L3 says nothing about classical hash functions**, which is how some published schemes actually
  fail (collision and second-preimage attacks).
- **L3 is only as good as the spec.** Hence `assumed_fields`.
- **L2's Azuma bound has a sensitivity floor**: corruption `c` is detectable only once
  `m > -2 ln(alpha)/c^2`.
- **Run-level analysis trusts the trace.** A real adversary does not hand you an honest log of
  their own cheating. The load-bearing contribution is the *scheme-level* analysis, which trusts
  nothing the adversary produces.
- **The hardware run is calibration only.** No quantum speedup is claimed and none exists at this
  scale.
- **`paired_pauli_Z` is reported as "no forgery attempted"** because Z does not alter a
  computational-basis message. It is still a valid signature-level attack on a superposition
  message; the message-changed criterion simply does not register it. Stated so the row is not
  misread.
- **We implement schemes that are known to be broken, on purpose.** We make no claim that any
  implemented scheme is secure.

---

## 8. Provenance of the numbers

Every figure in this document is either produced by `.venv/bin/python -m pauliguard.evaluation`,
pinned by a test in `tests/`, or recomputed by a supervisor audit script in `spike/`. The IBM
hardware floor carries a job id. Nothing here is asserted from memory.
