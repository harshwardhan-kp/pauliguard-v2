# PauliGuard v2

**Quantum-Inspired Cyber Threat Detection for Digital Signature Security**  
**SIH26141**

A rigorous, layered verification and falsification framework for Arbitrated Quantum Signature (AQS) schemes that couples finite-population channel statistics with exact $\text{GF}(2)$ symplectic algebraic analysis to catch statistically invisible probability-1 forgeries.

---

## The Finding

In Arbitrated Quantum Signature (AQS) schemes based on quantum teleportation and Quantum One-Time Pad (QOTP) or Clifford encryption, an attacker who intercepts the transmitted message and signature can forge a valid signature on an altered message with **probability exactly 1.0**. 

Because the attack operator commutes through the encryption layer up to a global phase, the forged quantum state is **mathematically identical** to an honest execution on the modified message. Statistical anomaly detectors, decoy-state analysis, and physical channel metrics are **structurally blind** to this attack:

$$\begin{aligned}
1. & \quad V = E_k U E_k^\dagger \in \mathcal{P}_n \quad \text{for any Clifford encryption } E_k \text{ and Pauli operator } U \in \mathcal{P}_n \\
2. & \quad E_k (U|P\rangle) = (E_k U E_k^\dagger)(E_k|P\rangle) = V |S\rangle \implies \text{Arbitrator predicate } E_k|P'\rangle = |S'\rangle \text{ holds } \forall k \in \mathcal{K} \\
3. & \quad \text{For QOTP } E_k = X^a Z^b, \; V = (-1)^{a \cdot z(U) \oplus b \cdot x(U)} U = \pm U \implies \text{Pauli letters invariant to key } k \\
4. & \quad \rho_{\text{forged}} = \operatorname{decrypt}\big(V \cdot \operatorname{encrypt}(|M\rangle\langle M|) \cdot V^\dagger\big) = U |M\rangle\langle M| U^\dagger = \rho_{\text{honest}(U|M\rangle)}
\end{aligned}$$

### Measured Evidence
- **Trace Distance:** $\text{Tr}\big(\rho_{\text{forged}}, \rho_{\text{honest}(U|M\rangle)}\big) = \mathbf{0.000\text{e}+00}$ across all keys, Pauli attack operators, and message states.
- **Total Variation Distance:** $\max \text{TVD} = \mathbf{0.000\text{e}+00}$ across 40 random projective measurement bases.
- **Empirical Verification:** The arbitrator predicate is satisfied in **12,852/12,852** independently evaluated cases ($17,136$ sweep evaluations across $n \in \{1, 2, 3\}$), yielding an empirical forgery success rate of **$1.000$**.
- **Control:** The unpaired attack (tampering with message only while leaving signature untouched) is detected and rejected **252/252** times ($100\%$).

Because the forged density matrix matches an honest run on $U|M\rangle$ exactly, no statistical measurement—regardless of sample size, basis selection, or collective multi-round measurements—can separate the two executions. Detection requires algebraic falsification at the scheme level.

---

## Install and Run

PauliGuard runs on Python 3.12 (using `.venv` provisioned via `uv`).

```bash
# Run the full automated test suite (155 tests)
.venv/bin/python -m pytest -q

# Run the complete evaluation matrix and noise benchmark harness
.venv/bin/python -m pauliguard.evaluation
```

---

## The Four Layers

PauliGuard structures threat detection across four independent, complementary layers. Statistical layers handle physical channel attacks; deterministic and algebraic layers handle structural protocol vulnerabilities.

| Layer | What It Computes | What It Detects | What It Is Blind To | Threshold Type |
|:---|:---|:---|:---|:---:|
| **L0 Conformance** | Deterministic trace schema validation, procedure sequence checking ($INIT \to SIGN \to VERIFY$), verifier authorization, and stateful cross-run key/nonce ledger tracking. | Replay of valid sessions/nonces, single-use key reuse, omitted protocol procedures, unauthorized verifiers. | Physical channel noise, in-transit quantum tampering, validly encrypted forged states. | **None**<br>(Deterministic predicate; 0 FPR by construction) |
| **L1 Channel Statistics** | One-sided Serfling finite-population tail bound over decoy-state error rates relative to measured hardware baseline floor: $\tau = \sqrt{\frac{-\ln(\alpha)(1 - (k-1)/N)}{2k}}$. | Intercept-resend eavesdropping, random Pauli perturbations on decoy states, coherent channel noise. | Paired-Pauli forgeries (decoys unperturbed; excess QBER = 0.000), replay attacks, key reuse. | **Runtime Floor-Relative**<br>($\tau$ relative to hardware floor $0.034424$) |
| **L2 Entanglement Quality** | Azuma-Hoeffding martingale concentration inequality over stabilizer generator verification shots for distributed entangled resource states ($|\xi\rangle$). | Malicious or degraded entanglement distribution, depolarized EPR pairs, multi-qubit resource corruption. | Paired-Pauli attacks on encrypted transmission (resource generation untouched), replay, key reuse. | **Runtime Martingale**<br>($\tau = \sqrt{\frac{-2\ln(\alpha)}{m}}$) |
| **L3 Algebraic Malleability** | Symplectic linear algebra over $\text{GF}(2)$ computing the kernel of the Clifford commutation relations $(M_{E_k} \oplus I)\vec{v}_U = \vec{0} \pmod 2$. | Paired-Pauli forging subspaces, scheme-level encryption malleability, operator commutation vulnerabilities. | Statistical channel noise, runtime channel eavesdropping, replay of old valid traces. | **None**<br>(Exact algebraic nullspace solver over $\text{GF}(2)$) |

---

## Results

Empirical results from the PauliGuard Evaluation Harness (`results/evaluation_matrix.md`, $n = 300$ trials per attack, noise $p = 0.0$, security parameter $\alpha = 10^{-10}$, decoy rounds $m = 400$, measured hardware floor $= 0.034424$ from `ibm_kingston`):

### Table 1: Attack Outcomes

| Attack | Forgery Success Rate | Status |
|:---|:---:|:---:|
| honest | 0.000 [0.000, 0.012] n=300 | NO FORGERY ATTEMPTED |
| paired_pauli_X | 1.000 [0.988, 1.000] n=300 | SUCCEEDS |
| paired_pauli_Y | 1.000 [0.988, 1.000] n=300 | SUCCEEDS |
| paired_pauli_Z | 0.000 [0.000, 0.012] n=300 | NO FORGERY ATTEMPTED |
| unpaired_pauli | 0.000 [0.000, 0.012] n=300 | DEFEATED BY PROTOCOL |
| intercept_resend | 0.000 [0.000, 0.012] n=300 | NO FORGERY ATTEMPTED |
| replay | 0.000 [0.000, 0.012] n=300 | NO FORGERY ATTEMPTED |
| key_reuse | 0.000 [0.000, 0.012] n=300 | NO FORGERY ATTEMPTED |

### Table 2: Detection by Layer

| Attack | L0 | L1 | L2 | L3 | ANY |
|:---|:---:|:---:|:---:|:---:|:---:|
| honest | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 |
| paired_pauli_X | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 | 1.000 [0.988, 1.000] n=300 |
| paired_pauli_Y | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 | 1.000 [0.988, 1.000] n=300 |
| paired_pauli_Z | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 | 1.000 [0.988, 1.000] n=300 |
| unpaired_pauli (defeated by protocol) | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 |
| intercept_resend | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 |
| replay | 1.000 [0.988, 1.000] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 |
| key_reuse | 1.000 [0.988, 1.000] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 0.000 [0.000, 0.012] n=300 | 1.000 [0.988, 1.000] n=300 |

### False Positive Curve Across Channel Noise Levels

| Noise Level (p) | L0 FPR | L1 FPR | L2 FPR | L3 FPR | ANY FPR |
|:---|:---:|:---:|:---:|:---:|:---:|
| 0.0000 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |
| 0.0010 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |
| 0.0100 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |
| 0.0500 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |

### Structural Blindness Analysis
- **STRUCTURAL BLINDNESS:** `paired_pauli_X` succeeds $1.000$ of the time and L1 detects it $0.000$ $[0.000, 0.012]$ of the time ($n=300$).
- **STRUCTURAL BLINDNESS:** `paired_pauli_X` succeeds $1.000$ of the time and L2 detects it $0.000$ $[0.000, 0.012]$ of the time ($n=300$).
- **STRUCTURAL BLINDNESS:** `paired_pauli_Y` succeeds $1.000$ of the time and L1 detects it $0.000$ $[0.000, 0.012]$ of the time ($n=300$).
- **STRUCTURAL BLINDNESS:** `paired_pauli_Y` succeeds $1.000$ of the time and L2 detects it $0.000$ $[0.000, 0.012]$ of the time ($n=300$).

---

## What We Claim / What We Do NOT Claim

### What We Claim
1. **L3 is Sound, Not Complete:** When L3 emits a certificate, it guarantees the existence of a probability-1 paired-Pauli forgery family for that scheme and constructs an explicit, executable witness.
2. **Zero False Positives by Construction (L0):** Spec-conforming honest executions never trigger L0 findings.
3. **Finite-Population Statistical Guarantees (L1):** By modeling decoy rounds without replacement using Serfling's inequality ($11.67\times$ tighter than Hoeffding at $k=4096, N=16384, \tau=0.03$), L1 rigorously upper-bounds false alarms relative to calibrated hardware noise floors.
4. **Structural Blindness is a Proven Theorem:** The 0.000 detection rate of statistical detectors on paired-Pauli forgeries is a direct consequence of zero trace distance ($\text{Tr}(\rho_F, \rho_H) = 0.000\text{e}+00$), not a calibration or sensitivity defect.

### What We Do NOT Claim
1. **We Never Prove a Scheme Secure:** Absence of an L3 certificate does not certify absolute security against arbitrary non-Pauli attacks, non-Clifford operations, or multi-party collusion. PauliGuard is an automated falsifier, not a general proof assistant.
2. **No AI/ML Anywhere in the Detection Path:** No neural networks, random forests, or fitted statistical heuristics are used. Security parameters must carry exact, provable analytical concentration bounds.
3. **No Quantum Speedup:** PauliGuard runs entirely on classical architectures. Quantum simulation (via Stim) is used exclusively for protocol execution and verification.
4. **Hardware Calibration Only:** Physical quantum execution (`ibm_kingston`, Heron r2, 4096 shots) was performed solely to calibrate realistic device error floors ($0.0344238$), establishing that absolute thresholds $\tau \le 0.03$ are unusable in physical deployments.
5. **No Hardcoded Numeric Thresholds:** Every threshold is computed dynamically at runtime from declared security parameters ($\alpha$), sample sizes ($k$), population sizes ($N$), and calibrated device floors.

---

## Repository Layout

```
pauliguard-v2/
├── pauliguard/
│   ├── evaluation.py          # D7 evaluation harness, matrix generator, and Clopper-Pearson reporter
│   ├── attacks/
│   │   └── paired_pauli.py    # Probability-1 paired-Pauli forgery generator and density matrix verifier
│   ├── detectors/
│   │   ├── layer0.py          # L0 deterministic conformance detector and cross-run session ledger
│   │   ├── layer1.py          # L1 channel-statistics detector using floor-relative Serfling bounds
│   │   ├── layer2.py          # L2 entanglement quality detector using Azuma-Hoeffding bounds
│   │   └── layer3.py          # L3 algebraic malleability detector and GF(2) symplectic solver
│   ├── engine/
│   │   ├── encryption.py      # Quantum encryption models (QOTP, Chained-CNOT) and Clifford tableaux
│   │   ├── pauli.py           # N-qubit Pauli operator representations and phase tracking over GF(2)
│   │   ├── protocol.py        # ProtocolEngine orchestrator with Stim teleportation circuits
│   │   ├── spec_loader.py     # YAML parser and dataclass validator for SchemeSpec definitions
│   │   └── trace.py           # Frozen Trace schema v1.1 and structural validation rules
│   └── specs/
│       ├── lu-2022.yaml       # Lu et al. (2022) 5-qubit stabilizer state AQS specification
│       ├── li-chan-long-2009.yaml # Li-Chan-Long (2009) Bell-state AQS specification
│       └── decoy-bb84-qds.yaml# Decoy-state BB84 QDS specification (contrast case)
├── results/
│   ├── floor_ibm_kingston.json# Measured IBM Kingston hardware error floor (141/4096 = 0.034424)
│   ├── evaluation_matrix.md   # Benchmark evaluation matrix with exact Clopper-Pearson intervals
│   └── evaluation_matrix.json # Machine-readable evaluation matrix output
└── docs/
    └── corrections.md         # Analytical corrections to proposal arithmetic and threshold formulas
```

---

## Provenance

A foundational risk for the teleportation-based AQS lineage was whether the 5-qubit resource state defined by Lu et al. (*Entropy* 24, 111, 2022),

$$|\xi\rangle = \frac{1}{2}\big(|100\rangle|\Psi_0\rangle + |111\rangle|\Psi_1\rangle + |001\rangle|\Psi_2\rangle + |010\rangle|\Psi_3\rangle\big)$$

was a genuine stabilizer state. This was resolved **YES** through two independent mathematical methods:

1. **NumPy Exhaustive Brute Force:** Evaluated all $4^5 = 1024$ Pauli operators; exactly **32** satisfy $|\langle\xi|P|\xi\rangle| = 1$ ($2^5$ required for a 5-qubit stabilizer state), spanning a support of 8 computational basis states with amplitudes $\pm 1/(2\sqrt{2})$.
2. **Stim Stabilizer Tableau Synthesis:** Stim synthesized the 5 generators and reproduced the identical statevector with a maximum amplitude deviation of $\mathbf{5.55\text{e}-17}$.

### Stabilizer Generators
$$\begin{aligned}
g_1 &= -I I Z Y Y \\
g_2 &= +I X X Z I \\
g_3 &= +I Y X Y X \\
g_4 &= +X I X I X \\
g_5 &= +Y I X Z Y
\end{aligned}$$

Because all required protocol operations ($H, X, Y, Z, S, CNOT, CZ, SWAP$) belong to the Clifford group, the Stim simulation backend and the $\text{GF}(2)$ symplectic algebraic malleability search are mathematically rigorous and sound.
