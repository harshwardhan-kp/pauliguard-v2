"""R1 spike: is Lu et al. (Entropy 24,111) |xi> a stabilizer state?

|xi> = 1/2 ( |100>|Psi0> + |111>|Psi1> + |001>|Psi2> + |010>|Psi3> )
Qubit order: q0q1q2 = the 3-qubit register, q3q4 = the Bell register.

Method: a 5-qubit stabilizer state is stabilised by exactly 2^5 = 32 Pauli
operators (up to sign), i.e. exactly 32 Pauli strings P with |<xi|P|xi>| == 1.
Anything less means it is NOT a stabilizer state.
"""
import itertools, numpy as np

I2 = np.eye(2); X = np.array([[0,1],[1,0]],dtype=complex)
Y = np.array([[0,-1j],[1j,0]]); Z = np.array([[1,0],[0,-1]],dtype=complex)
PAULI = {"I":I2,"X":X,"Y":Y,"Z":Z}

BELL = {  # standard convention
 0: {(0,0): 1/np.sqrt(2), (1,1): 1/np.sqrt(2)},
 1: {(0,0): 1/np.sqrt(2), (1,1):-1/np.sqrt(2)},
 2: {(0,1): 1/np.sqrt(2), (1,0): 1/np.sqrt(2)},
 3: {(0,1): 1/np.sqrt(2), (1,0):-1/np.sqrt(2)},
}
TERMS = [((1,0,0),0), ((1,1,1),1), ((0,0,1),2), ((0,1,0),3)]

def build(bell_map):
    psi = np.zeros(32, dtype=complex)
    for trip, b in TERMS:
        for (c,d), amp in bell_map[b].items():
            idx = (trip[0]<<4)|(trip[1]<<3)|(trip[2]<<2)|(c<<1)|d
            psi[idx] += 0.5*amp
    return psi

def kron(labels):
    M = np.array([[1]],dtype=complex)
    for L in labels: M = np.kron(M, PAULI[L])
    return M

def analyse(psi, name):
    assert abs(np.vdot(psi,psi)-1) < 1e-12, "not normalised"
    support = int(np.sum(np.abs(psi) > 1e-12))
    amps = sorted({round(float(np.real(a)),6) for a in psi if abs(a)>1e-12})
    stab, anti = [], 0
    for labels in itertools.product("IXYZ", repeat=5):
        ev = np.vdot(psi, kron(labels) @ psi)
        if abs(abs(ev)-1) < 1e-9:
            sign = int(np.sign(np.real(ev)))
            stab.append(("".join(labels), sign))
            if sign < 0: anti += 1
    print(f"--- {name} ---")
    print(f"support (nonzero basis states): {support}  (2^k? {support and (support & (support-1))==0})")
    print(f"distinct real amplitudes: {amps}")
    print(f"Paulis with |<xi|P|xi>|=1 : {len(stab)}   (need exactly 32)")
    print(f"  of which negative sign  : {anti}")
    print(f"VERDICT: {'STABILIZER STATE' if len(stab)==32 else 'NOT a stabilizer state'}")
    return stab

stab = analyse(build(BELL), "standard Bell convention")

# generators: pick 5 independent ones, then verify they generate all 32
if len(stab) == 32:
    import numpy.linalg as la
    def vec(s):
        v=[]
        for ch in s:
            v += {"I":[0,0],"X":[1,0],"Z":[0,1],"Y":[1,1]}[ch]
        return np.array(v)%2
    def rank(rows):
        M=np.array(rows)%2; r=0; R=M.copy().astype(int); nr,nc=R.shape
        for c in range(nc):
            piv=None
            for i in range(r,nr):
                if R[i,c]: piv=i;break
            if piv is None: continue
            R[[r,piv]]=R[[piv,r]]
            for i in range(nr):
                if i!=r and R[i,c]: R[i]=(R[i]+R[r])%2
            r+=1
        return r
    gens=[]
    for s,sg in stab:
        if s=="IIIII": continue
        trial=gens+[vec(s)]
        if rank(trial)>rank(gens) if gens else True:
            gens.append(vec(s)); 
            if len(gens)==5: break
    print(f"\nindependent generators found: {len(gens)} (rank {rank(gens)})")
    print("first 5 stabilizer generators (sign, string):")
    shown=0
    seen=[]
    for s,sg in stab:
        if s=="IIIII": continue
        t=seen+[vec(s)]
        if (rank(t)>rank(seen)) if seen else True:
            seen.append(vec(s)); print(f"   {'+' if sg>0 else '-'}{s}"); shown+=1
            if shown==5: break
