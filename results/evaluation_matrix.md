# PauliGuard Evaluation Matrix

**SIH26141** · Quantum-Inspired Cyber Threat Detection for Digital Signature Security
**Evaluation Harness Report (Deliverable D7)**

## Evaluation Matrix (noise_p = 0.0, alpha = 1e-10, n = 300)

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

### Notes on Asymmetry and Interpretation:
- **L3 is scheme-level**: It verifies algebraic malleability over GF(2) for the scheme specification and encryption model. When a certificate exists, it covers the entire paired-Pauli family with probability 1.0. It does not perform per-trace statistical sampling at runtime.
- **Honest rows** report the **False Positive Rate (FPR)**.
- **Defeated attacks**: Attacks annotated with `(defeated by protocol)` (such as `unpaired_pauli`) are rejected outright by the protocol verification predicate. A 0.000 detection rate reflects that the attack never succeeded in forging a signature, requiring no secondary detector activation.
- **Structural Blindness**: Zero rates for L1 and L2 on genuinely successful attacks (`forgery_succeeded > 0`, e.g. `paired_pauli_X`, `paired_pauli_Y`) represent **STRUCTURAL BLINDNESS** theorems, not detector defects.

## False Positive Curve Across Channel Noise Levels

| Noise Level (p) | L0 FPR | L1 FPR | L2 FPR | L3 FPR | ANY FPR |
|:---|:---:|:---:|:---:|:---:|:---:|
| 0.0000 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |
| 0.0010 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |
| 0.0100 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |
| 0.0500 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 | 0.000 [0.000, 0.018] n=200 |

## Structural Blindness Analysis

- **STRUCTURAL BLINDNESS: paired_pauli_X succeeds 1.000 of the time and L1 detects it 0.000 [0.000, 0.012] of the time (n=300)**
- **STRUCTURAL BLINDNESS: paired_pauli_X succeeds 1.000 of the time and L2 detects it 0.000 [0.000, 0.012] of the time (n=300)**
- **STRUCTURAL BLINDNESS: paired_pauli_Y succeeds 1.000 of the time and L1 detects it 0.000 [0.000, 0.012] of the time (n=300)**
- **STRUCTURAL BLINDNESS: paired_pauli_Y succeeds 1.000 of the time and L2 detects it 0.000 [0.000, 0.012] of the time (n=300)**
