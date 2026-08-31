"""SUPERVISOR independent verification of THE HEADLINE CLAIM.
Everything here is rebuilt from first principles in numpy. The only worker
artefacts touched are the two functions whose OUTPUT is being audited."""
import itertools, numpy as np, sys
sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.pauli import Pauli
from pauliguard.engine.encryption import QOTP
from pauliguard.attacks.paired_pauli import (paired_pauli_attack, predicate_holds,
                                             forged_and_honest_density_matrices)

I2=np.eye(2,dtype=complex); X=np.array([[0,1],[1,0]],dtype=complex)
Z=np.array([[1,0],[0,-1]],dtype=complex)
def kron(ms):
    R=np.array([[1]],dtype=complex)
    for m in ms: R=np.kron(R,m)
    return R
def Ek(a,b,n): return kron([(X if a[i] else I2)@(Z if b[i] else I2) for i in range(n)])
def norm(v): return v/np.linalg.norm(v)

rng=np.random.default_rng(11); q=QOTP(); fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

# ---- A. predicate satisfied identically, rebuilt entirely in numpy ----
count=0
for n in (1,2,3):
    dim=2**n
    states=[np.eye(dim,dtype=complex)[0], norm(np.ones(dim,dtype=complex)),
            norm(rng.normal(size=dim)+1j*rng.normal(size=dim))]
    for a in itertools.product((0,1),repeat=n):
      for b in itertools.product((0,1),repeat=n):
        E=Ek(a,b,n); Ed=E.conj().T
        for letters in itertools.product("IXYZ",repeat=n):
            if set(letters)=={"I"}: continue
            U=Pauli.from_string("+"+"".join(letters)); Um=U.to_matrix()
            V=E@Um@Ed                       # V built WITHOUT stim
            for M in states:
                lhs=E@(Um@M); rhs=V@(E@M)
                k=np.argmax(np.abs(lhs))
                ph=lhs[k]/rhs[k] if abs(rhs[k])>1e-12 else 1
                chk(np.allclose(lhs, ph*rhs, atol=1e-9), f"predicate n={n}")
                count+=1
print(f"[A] arbitrator predicate satisfied, rebuilt in pure numpy: {count} cases -> {'OK' if not fails else 'FAILED'}")

# ---- B. worker's predicate_holds agrees with my reconstruction ----
before=fails
for n in (1,2):
    dim=2**n; M=norm(rng.normal(size=dim)+1j*rng.normal(size=dim))
    for a in itertools.product((0,1),repeat=n):
      for b in itertools.product((0,1),repeat=n):
        for letters in itertools.product("IXYZ",repeat=n):
            U=Pauli.from_string("+"+"".join(letters))
            chk(predicate_holds(q,(a,b),n,U,M) is True, f"worker predicate_holds False n={n}")
print(f"[B] worker predicate_holds agrees with independent build: {'OK' if fails==before else 'FAILED'}")

# ---- C. THE STRONG FORM: trace distance between forged and honest is ZERO ----
before=fails; worst=0.0
for n in (1,2):
    dim=2**n
    for a in itertools.product((0,1),repeat=n):
      for b in itertools.product((0,1),repeat=n):
        for letters in itertools.product("IXYZ",repeat=n):
            if set(letters)=={"I"}: continue
            U=Pauli.from_string("+"+"".join(letters))
            M=norm(rng.normal(size=dim)+1j*rng.normal(size=dim))
            rf,rh=forged_and_honest_density_matrices(q,(a,b),n,M,U)
            # trace distance = 1/2 * sum |eigenvalues of (rf-rh)|
            td=0.5*np.sum(np.abs(np.linalg.eigvalsh(rf-rh)))
            worst=max(worst,td)
            chk(td<1e-12, f"nonzero trace distance {td:.2e}")
print(f"[C] max trace distance(forged, honest) over full sweep = {worst:.3e} -> {'OK (=0)' if fails==before else 'FAILED'}")
print("    trace distance 0 => NO measurement, however clever or collective, can distinguish them.")

# ---- D. CONTROL: unpaired attack must break the predicate ----
before=fails; broke=0; tot=0
for n in (1,2):
    dim=2**n; M=norm(rng.normal(size=dim)+1j*rng.normal(size=dim))
    for a in itertools.product((0,1),repeat=n):
      for b in itertools.product((0,1),repeat=n):
        E=Ek(a,b,n)
        for letters in itertools.product("IXYZ",repeat=n):
            if set(letters)=={"I"}: continue
            U=Pauli.from_string("+"+"".join(letters)).to_matrix()
            lhs=E@(U@M); rhs=E@M          # signature NOT updated
            k=np.argmax(np.abs(lhs)); ph=lhs[k]/rhs[k] if abs(rhs[k])>1e-12 else 1
            tot+=1
            if not np.allclose(lhs, ph*rhs, atol=1e-9): broke+=1
chk(broke>0,"unpaired control never breaks -> test 1 would be vacuous")
print(f"[D] CONTROL unpaired attack detected {broke}/{tot} -> {'OK (non-vacuous)' if fails==before else 'FAILED'}")

# ---- E. empirical: Born-rule outcome distributions under random measurement bases ----
before=fails; worst_tv=0.0
for trial in range(40):
    n=2; dim=4
    a=tuple(rng.integers(0,2,n)); b=tuple(rng.integers(0,2,n))
    U=Pauli.from_string("+"+"".join(np.array(list("XYZ"))[rng.integers(0,3,n)]))
    M=norm(rng.normal(size=dim)+1j*rng.normal(size=dim))
    rf,rh=forged_and_honest_density_matrices(q,(a,b),n,M,U)
    W=np.linalg.qr(rng.normal(size=(dim,dim))+1j*rng.normal(size=(dim,dim)))[0]  # random basis
    pf=np.real(np.diag(W.conj().T@rf@W)); phh=np.real(np.diag(W.conj().T@rh@W))
    worst_tv=max(worst_tv, 0.5*np.sum(np.abs(pf-phh)))
chk(worst_tv<1e-12, f"outcome distributions differ, TV={worst_tv:.2e}")
print(f"[E] max total-variation distance over 40 RANDOM measurement bases = {worst_tv:.3e} -> {'OK' if fails==before else 'FAILED'}")

print("\n"+("HEADLINE CLAIM INDEPENDENTLY CONFIRMED" if fails==0 else f"{fails} CHECKS FAILED"))
sys.exit(1 if fails else 0)
