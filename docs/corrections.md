# Corrections to the proposal and dossier, found by verification

Every number below was recomputed from scratch. The dossier itself said
"check these yourself, do not trust the arithmetic here blindly" — this is that check.

## 1. The false-positive claim on Slide 2 is overstated (MATTERS — fix the deck)

> "At m = 4096 decoy rounds and τ = 0.03, legitimate signatures are rejected
>  with probability below 0.06%."

The one-sided Hoeffding bound exp(−2mτ²) at m=4096, τ=0.03 is **0.0628%**, which
is **above** 0.06%. The claim as written is false.

**Fix adopted:** default m = **4200**, giving **0.0521%** — "below 0.06%" is then true.
Alternatives: keep m=4096 and say "below 0.07%", or "approximately 0.063%".

## 2. Three of four rows in the dossier's Hoeffding table are wrong (Part VI, §6.1)

| m | τ | dossier | correct |
|---|---|---|---|
| 1024 | 0.03 | 0.158% | **15.83%** (100× — the fraction 0.1583 written with a % sign) |
| 4096 | 0.03 | 0.0628% | 0.0628% ✅ correct |
| 4096 | 0.05 | 0.0000013% | **0.00000013%** (10×) |
| 8192 | 0.02 | 0.156% | **0.1425%** |

Only the m=4096/τ=0.03 row is right. Do not quote the others.

## 3. The measured hardware floor invalidates an absolute τ (MATTERS)

Measured on `ibm_kingston` (Heron r2), job `da8up31qtnsc73d0v7h0`, 4096 shots:
**error floor = 141/4096 = 0.03442**, 95% CI [0.0288, 0.0400].

This is **above** the proposed τ=0.03. An absolute threshold of 0.03 would reject
honest signatures on real hardware. τ must be applied **relative to the measured
floor**: flag iff (x̄ − 0.0344) ≥ τ. `test_absolute_tau_would_reject_honest_hardware_signatures`
pins this.

This is precisely the payoff the hardware run was for: competitors assume a
depolarising parameter, we measured one, and the measurement changed the design.

## 4. Attack A's undetectability is stronger than the dossier hedged

Dossier §12.2 lists "is Attack A provably undetectable by ANY measurement?" as an
open question needing care. It is settled: `decrypt(U·encrypt(ρ)) = UρU†` holds
**exactly** for every key, so the forged and honest executions are the *same
density matrix*. No measurement — including collective measurements across many
rounds — can separate them. Gate 6 is a theorem, not an empirical observation.

State it precisely: what is proven is indistinguishability from an honest run on
the *modified* message U|M⟩. That is exactly what makes the arbitrator accept.
