"""SUPERVISOR audit of the SWAP-test fix.
Derives the acceptance probability from the ACTUAL SWAP-test circuit
(Hadamard - controlled-SWAP - Hadamard) rather than from the closed form."""
import sys, numpy as np; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.pauli import Pauli
from pauliguard.detectors.swap_test import (swap_test_accept_probability,
    swap_test_detect_probability, detection_probability_k_copies, copies_needed,
    SwapTestVerifier)
fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)
rng=np.random.default_rng(5)
def norm(v): return v/np.linalg.norm(v)

# --- build the real SWAP-test circuit and read off P(ancilla=0) ---
def circuit_accept_prob(psi, phi):
    d=len(psi); n=int(np.log2(d))
    # full state: |0>_anc (x) |psi> (x) |phi>
    state=np.zeros(2*d*d, dtype=complex)
    state[:d*d]=np.kron(psi,phi)              # ancilla |0> block
    # H on ancilla
    a0,a1=state[:d*d].copy(), state[d*d:].copy()
    state[:d*d]=(a0+a1)/np.sqrt(2); state[d*d:]=(a0-a1)/np.sqrt(2)
    # controlled-SWAP on the |1> ancilla block
    blk=state[d*d:].reshape(d,d)
    state[d*d:]=blk.T.reshape(-1)             # SWAP of the two registers
    # H on ancilla again
    a0,a1=state[:d*d].copy(), state[d*d:].copy()
    state[:d*d]=(a0+a1)/np.sqrt(2); state[d*d:]=(a0-a1)/np.sqrt(2)
    return float(np.vdot(state[:d*d],state[:d*d]).real)   # P(ancilla = 0) = accept

print("[1] closed form vs ACTUAL SWAP-test circuit (H, CSWAP, H):")
worst=0.0
for n in (1,2):
    d=2**n
    for _ in range(30):
        psi=norm(rng.normal(size=d)+1j*rng.normal(size=d))
        phi=norm(rng.normal(size=d)+1j*rng.normal(size=d))
        got=swap_test_accept_probability(psi,phi); want=circuit_accept_prob(psi,phi)
        worst=max(worst,abs(got-want)); chk(abs(got-want)<1e-10,f"n={n} {got} vs {want}")
print(f"    max |closed_form - circuit| over 60 random pairs = {worst:.3e} -> {'OK' if not fails else 'FAILED'}")

# --- 2. ONE-SIDED ERROR: an honest signature is NEVER falsely rejected ---
before=fails
for n in (1,2,3):
    d=2**n
    for _ in range(40):
        psi=norm(rng.normal(size=d)+1j*rng.normal(size=d))
        chk(swap_test_accept_probability(psi,psi)==1.0,"honest state not accepted with prob exactly 1")
print(f"[2] ONE-SIDED ERROR: accept(psi,psi) == 1.0 exactly, 120 states -> {'OK' if fails==before else 'FAILED'}")
print("    => zero false rejection of honest signatures BY CONSTRUCTION (the 'deterministic")
print("       acceptance' the PS asks for, in the precise sense that is achievable).")

# --- 3. detection probabilities vs my own closed forms ---
before=fails
zero=np.array([1,0],dtype=complex)
X=Pauli.from_string("X"); Z=Pauli.from_string("Z"); Y=Pauli.from_string("Y")
chk(swap_test_detect_probability(zero,X)==0.5,"X on |0> should be exactly 0.5")
chk(swap_test_detect_probability(zero,Y)==0.5,"Y on |0> should be exactly 0.5")
chk(swap_test_detect_probability(zero,Z)==0.0,"Z on |0> should be exactly 0.0 (no power)")
print(f"[3] p_detect: X->{swap_test_detect_probability(zero,X)}  Y->{swap_test_detect_probability(zero,Y)}"
      f"  Z->{swap_test_detect_probability(zero,Z)} -> {'OK' if fails==before else 'FAILED'}")
print("    Z has NO power: <0|Z|0>=1, Z does not change the computational-basis message.")
chk(copies_needed(zero,Z,0.99)==-1,"copies_needed must return -1 when there is no power")

# --- 4. THE FIX CURVE: analytic vs Monte Carlo, computed by ME ---
print("[4] THE FIX: forgery detection probability once a SWAP test is added")
print("      k   analytic 1-2^-k   monte carlo (n=40000)   |diff|")
before=fails
for k in range(1,9):
    ana=detection_probability_k_copies(zero,X,k)
    mc=SwapTestVerifier(k_copies=k,seed=k).simulate(zero,X,40000)
    chk(abs(ana-(1-2.0**-k))<1e-12,f"analytic != 1-2^-k at k={k}")
    se=(ana*(1-ana)/40000)**0.5
    chk(abs(mc-ana)<=4*se+1e-9,f"MC {mc} vs analytic {ana} at k={k}")
    print(f"      {k}   {ana:<16.6f} {mc:<22.6f} {abs(mc-ana):.6f}")
print(f"    -> {'OK: empirical matches the bound' if fails==before else 'FAILED'}")

# --- 5. the comparison that makes the pitch ---
print("[5] SAME ATTACK, BEFORE AND AFTER THE FIX:")
print(f"      L1 statistical detection (measured earlier) : 0.0000   <- structurally blind")
print(f"      SWAP test, k=1                              : {detection_probability_k_copies(zero,X,1):.4f}")
print(f"      SWAP test, k=8                              : {detection_probability_k_copies(zero,X,8):.4f}")
print(f"      SWAP test, k=20                             : {detection_probability_k_copies(zero,X,20):.6f}")
print(f"      copies needed for 99.9% confidence          : {copies_needed(zero,X,0.999)}")

print("\n"+("ALL INDEPENDENT SWAP CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
