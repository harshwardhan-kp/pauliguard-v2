"""Independent cross-check of R1 using Stim's own tableau machinery.

If |xi> is a stabilizer state, Stim must be able to accept the 5 generators
found by the numpy search and reproduce the SAME state vector (up to global
phase). Two independent implementations agreeing is the validation bar.
"""
import numpy as np, stim, itertools

# rebuild |xi> exactly as in the numpy spike
BELL = {0:{(0,0):1,(1,1):1}, 1:{(0,0):1,(1,1):-1},
        2:{(0,1):1,(1,0):1}, 3:{(0,1):1,(1,0):-1}}
TERMS = [((1,0,0),0), ((1,1,1),1), ((0,0,1),2), ((0,1,0),3)]
psi = np.zeros(32, dtype=complex)
for trip,b in TERMS:
    for (c,d),s in BELL[b].items():
        idx=(trip[0]<<4)|(trip[1]<<3)|(trip[2]<<2)|(c<<1)|d
        psi[idx] += 0.5*(s/np.sqrt(2))

# full stabilizer group from Stim's perspective
gens = ["-IIZYY","+IXXZI","+IYXYX","+XIXIX","+YIXZY"]
try:
    t = stim.Tableau.from_stabilizers([stim.PauliString(g) for g in gens])
    sv = t.to_state_vector(endian="big")
    # compare up to global phase
    nz = np.argmax(np.abs(psi))
    phase = psi[nz]/sv[nz]
    err = np.max(np.abs(psi - phase*sv))
    print(f"Stim accepted the 5 generators as a valid stabilizer group: YES")
    print(f"max |psi_numpy - e^{{i.phi}} * psi_stim| = {err:.3e}")
    print(f"VERDICT: {'MATCH - two independent implementations agree' if err < 1e-9 else 'MISMATCH'}")
except Exception as e:
    print("Stim REJECTED the generators:", type(e).__name__, e)

# Clifford check on every gate the protocol needs
print("\n--- Clifford closure check on required gate set ---")
need = ["H","X","Y","Z","CNOT","SWAP","S","CZ"]
ok = []
for g in need:
    try:
        stim.Circuit(f"{g} " + ("0 1" if g in ("CNOT","SWAP","CZ") else "0"))
        ok.append(g)
    except Exception as e:
        print(f"  {g}: REJECTED {e}")
print(f"  Stim accepts all of {need}: {ok == need}")
print("  (Bell/GHZ prep = H+CNOT; Bell-basis measure = CNOT+H+MZ; all Clifford.)")
