# Iconography for the PauliGuard deck

Two sources, deliberately separated. Roughly half our architecture is mathematics, and
mathematics has no vendor logos. Borrowing one would be logo-washing.

## Tier 1 — real product logos (download these)

Get clean SVGs from **simpleicons.org** or **devicon.dev**. Both ship permissively-licensed
SVG sets (the marks themselves remain the trademarks of their owners).

| Where it goes | Logos |
|---|---|
| 2 · Execution engines | Python · NumPy · SciPy · Qiskit |
| 1 · Protocol spec / 3 · Trace | YAML · JSON |
| 9 · Serving | FastAPI · JavaScript · HTML5 · CSS3 |
| Test + CI | pytest · GitHub · Git · Playwright · Docker *(planned)* |
| 8 · Hardware calibration | IBM *(for IBM Quantum `ibm_kingston`)* |
| 6 · References slide | arXiv · MDPI/Entropy · APS *(Physical Review A)* |

**Two cautions.**
1. **Stim has no standalone brand mark.** It is `quantumlib`. Use a plain text badge or the
   Google Quantum AI mark — do not invent a logo for it.
2. **Do not place the IBM mark so it reads as endorsement.** Caption it
   "sub-circuit run on IBM Quantum hardware", never "in partnership with".

## Tier 1b — the rejected alternatives, shown greyed or struck through

NetSquid · QuTiP · SeQUeNCe · QuNetSim

Worth one small row. Our own proposal argues that *knowing why we did not use NetSquid is a
stronger signal to an evaluator than having used it*. A visual kill-list makes that argument
in about one second, and it pre-empts the "why not NetSquid?" question.

## Tier 2 — our own icon set (`icons.svg`)

20 monoline glyphs on a 48x48 grid, stroke 2, recolourable through `currentColor`.
No vendor logo exists for any of these concepts; they were drawn for this project.

| icon | used at |
|---|---|
| `ico-bell-pair` | EPR pair source and distribution |
| `ico-teleport` | state teleportation channel |
| `ico-pauli-x` / `ico-pauli-z` | bit-flip / phase-flip operators |
| `ico-pauli-group` | the n-qubit Pauli group |
| `ico-stabilizer` | L2 stabilizer generators |
| `ico-measurement` | projective measurement and readout |
| `ico-qubit-register` | qubit registers and lifetimes |
| `ico-entangle-break` | L2 resource degradation |
| `ico-swap-test` | the SWAP-test hardening fix |
| `ico-gf2-matrix` | GF(2) symplectic tableau |
| `ico-symplectic` | the symplectic form |
| `ico-nullspace` | L3 malleability subspace |
| `ico-threshold-curve` | Serfling tail bound |
| `ico-confidence-band` | Azuma martingale band |
| `ico-sampling` | hypergeometric decoy sampling (without replacement) |
| `ico-forgery` | paired-Pauli forgery |
| `ico-certificate` | **algebraic ATTACK certificate** |
| `ico-arbitrator` | Trent, the arbitrator |
| `ico-hardware-qpu` | the QPU backend |

### Usage
```html
<svg width="24" height="24"><use href="icons.svg#ico-stabilizer"/></svg>
```
Colour is inherited, so `<g color="#15713D">` recolours any icon without editing the file.

### One caption that matters
`ico-certificate` is captioned **"Algebraic ATTACK certificate"**, never "security
certificate". L3 emits a witness that an attack EXISTS. It never certifies that a scheme is
secure, and the iconography must not imply otherwise.
