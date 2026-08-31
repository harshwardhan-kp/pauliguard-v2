"""SUPERVISOR independent check of T2. Rebuilds E_k from scratch with numpy
kron products -- no stim, no worker code -- and checks the conjugation law.
This is THE load-bearing property of the whole project."""
import itertools, numpy as np, sys
sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.pauli import Pauli
from pauliguard.engine.encryption import QOTP, ChainedCNOT, pauli_letters_preserved

I2=np.eye(2,dtype=complex); X=np.array([[0,1],[1,0]],dtype=complex)
Z=np.array([[1,0],[0,-1]],dtype=complex)
def kron(ms):
    R=np.array([[1]],dtype=complex)
    for m in ms: R=np.kron(R,m)
    return R
def Ek_qotp(a,b,n):                    # independent E_k construction
    return kron([ (X if a[i] else I2) @ (Z if b[i] else I2) for i in range(n) ])

fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

# --- 1. QOTP: V = E U E^dag has the SAME letters as U, for every key, every U ---
q=QOTP()
for n in (1,2,3):
    for letters in itertools.product("IXYZ",repeat=n):
        if set(letters)=={"I"}: continue
        U=Pauli.from_string("+"+"".join(letters))
        chk(pauli_letters_preserved(q,n,U), f"QOTP letters not preserved n={n} U={letters}")
print(f"[1] QOTP preserves Pauli letters for ALL keys, n=1..3, all U : {'OK' if not fails else 'FAILED'}")

# --- 2. numpy-only cross-check of the conjugation, independent of stim ---
before=fails
for n in (1,2):
    for a in itertools.product((0,1),repeat=n):
        for b in itertools.product((0,1),repeat=n):
            E=Ek_qotp(a,b,n); Ed=E.conj().T
            for letters in itertools.product("IXYZ",repeat=n):
                U=Pauli.from_string("+"+"".join(letters))
                V=q.conjugate_attack((a,b),n,U)
                chk(np.allclose(V.to_matrix(), E@U.to_matrix()@Ed, atol=1e-12),
                    f"conj mismatch n={n} a={a} b={b} U={letters}")
print(f"[2] conjugate_attack == E_k U E_k-dagger (pure numpy, no stim) : {'OK' if fails==before else 'FAILED'}")

# --- 3. the SIGN is the only thing that changes, and it genuinely does flip ---
before=fails
flips=0; total=0
for a in itertools.product((0,1),repeat=2):
    for b in itertools.product((0,1),repeat=2):
        for letters in itertools.product("IXYZ",repeat=2):
            U=Pauli.from_string("+"+"".join(letters))
            V=q.conjugate_attack((a,b),2,U); total+=1
            if V.phase!=U.phase: flips+=1
print(f"[3] anticommuting (sign-flipping) instances exist: {flips}/{total} keys flip the sign  -> {'OK' if flips>0 else 'FAILED (suspicious)'}")
if flips==0: fails+=1

# --- 4. CONTRAST: chained-CNOT must NOT preserve letters ---
before=fails
c=ChainedCNOT()
broke=False
for n in (2,3):
    for letters in itertools.product("IXYZ",repeat=n):
        if set(letters)=={"I"}: continue
        U=Pauli.from_string("+"+"".join(letters))
        if not pauli_letters_preserved(c,n,U): broke=True; break
    if broke: break
chk(broke,"ChainedCNOT wrongly preserves letters for every U (contrast case is vacuous)")
print(f"[4] ChainedCNOT genuinely spreads letters (contrast is real) : {'OK' if fails==before else 'FAILED'}")

print("\n"+("ALL INDEPENDENT T2 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
