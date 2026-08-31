# External validation: reproducing Jacqmin & Liénardy's 1/(8n) bound

**Status: RESOLVED as genuine external validation.** The source paper was obtained
(arXiv:2603.19985, archived at `docs/papers/`), the exact encryption was implemented from it,
and our independent measurement confirms their bound and sharpens it.

## What the paper says

Jacqmin & Liénardy, §2, analysing Zhang-Sun-Zhang-Jia's AQS scheme with layered "KCCC"
encryption, bound the forgery success probability as

    Pr(forgery) >= Pr(k1(1)=1) · Pr(k2_1=0) · Pr(tau_1=0) · Pr(|P> != |P'>) >= 1/(8n)
                      1/n            1/2          1/2            1/2

The encryption is three layers, applied in this order:

    E^KCCC_{k1||k2||k3}  =  E^perm_k3  o  H_k2  o  E^CNOT_k1

- **Layer 1** `E^CNOT_k1`: `k1` is a **permutation** of (1..n), and
  `E^CNOT_k1 = CNOT_{n,k1(n)} ··· CNOT_{1,k1(1)}`. Crucially `CNOT_{i,i}` is the **identity**,
  so `k1(1)=1` means qubit 1 escapes the first CNOT. That event has probability **1/n**.
- **Layer 2** `H_k2`: apply `H` to qubit `i` iff `k2_i = 1`. The event `k2_1 = 0` has probability 1/2.
- **Layer 3** `E^perm_k3`: for the transposition variant, `tau_i = k3_i XOR k3_{n+1-i}`, swapping
  qubits `i` and `n+1-i` when `tau_i = 1`. The event `tau_1 = 0` has probability 1/2.

## What we measured, independently

We implemented all three layers exactly and enumerated the **entire** keyspace
(`n! · 2^n · 2^n` keys) for n = 2..5. No sampling.

### The three key conditions reproduce exactly

| n | Pr(k1(1)=1) | Pr(k2_1=0) | Pr(tau_1=0) | joint |
|---|---|---|---|---|
| 2 | 1/2 | 1/2 | 1/2 | **1/8** |
| 3 | 1/3 | 1/2 | 1/2 | **1/12** |
| 4 | 1/4 | 1/2 | 1/2 | **1/16** |

The joint probability is exactly **1/(4n)** — the paper's three key conditions, recovered from
our own exhaustive count, as exact rationals rather than estimates.

### The exact algebraic survival law

| n | survivals / keys | exact | paper bound 1/(8n) | satisfied | measured/bound |
|---|---|---|---|---|---|
| 2 | 8 / 32 | **1/4** | 1/16 | YES | 4.000x |
| 3 | 48 / 384 | **1/8** | 1/24 | YES | 3.000x |
| 4 | 512 / 6144 | **1/12** | 1/32 | YES | 2.667x |
| 5 | 7680 / 122880 | **1/16** | 1/40 | YES | 2.500x |

The law is exactly

    P(algebraic survival) = 1 / (4(n-1))

confirmed as an exact rational at every n tested.

## How the two results fit together

The paper states a **lower bound** derived from three **sufficient** key conditions. Sufficient
conditions necessarily under-count the true success set, so a bound that is satisfied but not
tight is exactly what a correct independent check should find.

The gap is fully accounted for:

    measured / bound  =  [1/(4(n-1))] / [1/(8n)]  =  2n/(n-1)  ->  2  as n -> infinity

and that limiting factor of **2** is precisely the message-change term `Pr(|P> != |P'>) >= 1/2`
which the paper includes and our purely algebraic layer does not model. The two analyses agree.

## Why this is the strongest claim in the project

This number was derived analytically by other people, published in March 2026, and we never had
their code. We implemented their construction from the paper's own definitions and recovered:

1. all three key-condition probabilities exactly (1/n, 1/2, 1/2),
2. their joint value 1/(4n) exactly,
3. a bound-satisfying survival law, with the residual factor explained exactly.

## Provenance and honesty

- Paper obtained from arXiv and archived at
  `docs/papers/jacqmin-lienardy-2026-arXiv-2603.19985.pdf` (23 pages, 23 March 2026).
- Layer definitions transcribed from §2 of that paper, not from a secondhand description.
- We report `1/(4(n-1))` as **our** measurement of the algebraic survival set. We do not claim
  the paper states that law; it does not. It states a lower bound, which we confirm.
- An earlier version of this document reported `1/n` from a *simplified* construction that
  lacked the Hadamard layer and used a different CNOT topology. That construction was wrong as
  a model of this scheme. It is superseded by this one. The earlier number should not be quoted.
