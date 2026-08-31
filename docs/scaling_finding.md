# Finding: forgery survival under permuted chained-CNOT scales exactly as 1/n

**Status: our own result, derived from our own construction. NOT a reproduction of any
published bound.** See the honesty note at the bottom before quoting this anywhere.

## What we computed

For an adversary who does not know the key, the attack operator `U` must be **fixed in
advance**. The success probability is therefore the fraction of keys for which that fixed `U`
still satisfies the arbitrator predicate. We enumerated the **entire** key space
(`4^n · n!` keys: X/Z layer, CNOT chain, qubit permutation) and counted exactly.

## Result

Of all `3n` weight-1 attacks, exactly **two** survive at any rate:

| n | keyspace | surviving weight-1 attacks | survival | exact | rate x n |
|---|---|---|---|---|---|
| 2 | 32 | `Z` on qubit 0, `X` on qubit 1 | 16/32 | **1/2** | 1.0000 |
| 3 | 384 | `Z` on qubit 0, `X` on qubit 2 | 128/384 | **1/3** | 1.0000 |
| 4 | 6144 | `Z` on qubit 0, `X` on qubit 3 | 1536/6144 | **1/4** | 1.0000 |

`rate x n = 1.0000` at every n, with **zero** fitting error. The law is exactly

    P(forgery survives) = 1/n

## Why those two operators, and nothing else

The CNOT chain `CNOT(0->1), CNOT(1->2), ..., CNOT(n-2 -> n-1)` propagates **X-type** errors
**forward** and **Z-type** errors **backward**. An `X` on qubit 0 therefore spreads across every
downstream qubit and cannot be matched by a fixed signature-side operator; likewise a `Z` on the
last qubit spreads upstream. The only two non-spreading operators are:

- **`X` on the tail** (qubit `n-1`) — nothing downstream to spread into
- **`Z` on the head** (qubit `0`) — nothing upstream to spread into

Everything else is destroyed by the chain. The residual `1/n` is the probability that the
random qubit permutation `tau` places the attacked qubit back at the position the fixed attack
assumed.

**Consequence worth stating on stage:** chaining alone does not stop the attack; it only makes
it *positional*. The permutation is what converts a probability-1 forgery into a probability-1/n
one. That is a design lesson, not a fix — 1/n is not negligible for small n.

## Which of the two actually forges a message

`Z` on qubit 0 is a **phase** flip: it does not alter a computational-basis message. The
message-changing survivor is **`X` on qubit n-1**, at rate `1/n`. Counting the `Z` survivor as a
forgery would overstate the attack surface, so we separate them.

## HONESTY NOTE — read before quoting

The figure cited secondhand in our project context for this scheme family is **1/(8n)**. We
measured **1/n**. The ratio is exactly **8 = 2^3**, which is consistent with three additional
independent single-bit key conditions present in the published construction (the context
mentions conditions of the form `k1 = 1`, `k2 = 0`, `tau_1 = 0`) that our implementation does
not model.

**We did not have the source paper.** We implemented the mechanism from a secondhand
description. We therefore:

- do **not** claim to reproduce, match, or validate the published `1/(8n)` bound;
- report `1/n` as a property of **our** construction, exactly computed over the full key space;
- flag the factor-8 gap as a **known, characterised difference**, not as agreement.

We deliberately did **not** tune our construction until it produced `1/(8n)`. Fitting a
construction to a target number would have destroyed the only thing that makes this result
worth anything.

**To close this gap properly**, obtain arXiv:2603.19985 and implement the exact key schedule.
That is a one-hour task once the paper is in hand, and it would convert this from "our result"
into a genuine external-validation result — the strongest single claim available to the project.
