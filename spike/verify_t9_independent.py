"""SUPERVISOR audit of L3 -- the differentiating layer. Verified from first principles."""
import sys, numpy as np, stim, itertools; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.detectors.layer3 import (Layer3, gf2_rank, gf2_nullspace, gf2_solve,
                                         clifford_to_symplectic, pauli_to_vector, vector_to_pauli)
from pauliguard.engine.pauli import Pauli, conjugate
from pauliguard.engine.spec_loader import discover_specs
from pauliguard.engine.encryption import QOTP
fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)
rng=np.random.default_rng(3)

# 1. GF(2) nullspace genuinely satisfies M v = 0 and rank-nullity holds
before=fails
for _ in range(150):
    r,c=int(rng.integers(1,7)),int(rng.integers(1,8))
    M=rng.integers(0,2,(r,c)).astype(np.uint8)
    ns=gf2_nullspace(M); rk=gf2_rank(M)
    for v in ns: chk(not (M@v %2).any(), "nullspace vector not in kernel")
    chk(rk+len(ns)==c, f"rank-nullity violated: {rk}+{len(ns)} != {c}")
    # brute-force rank cross-check for tiny matrices
    if c<=8:
        span={0}
        rows=[int("".join(map(str,row)),2) for row in M]
        for k in range(1,1<<len(rows)):
            acc=0
            for i,rw in enumerate(rows):
                if k>>i & 1: acc^=rw
            span.add(acc)
        chk(len(span)==2**rk, f"rank {rk} inconsistent with span size {len(span)}")
print(f"[1] GF(2) nullspace/rank vs brute-force span: {'OK' if fails==before else 'FAILED'}")

# 2. symplectic form preserved: M^T J M == J  (my own J)
before=fails
for n in (1,2,3):
    J=np.block([[np.zeros((n,n),dtype=np.uint8),np.eye(n,dtype=np.uint8)],
                [np.eye(n,dtype=np.uint8),np.zeros((n,n),dtype=np.uint8)]])
    for _ in range(25):
        T=stim.Tableau.random(n); M=clifford_to_symplectic(T,n)
        chk(np.array_equal((M.T@J@M)%2, J), f"not symplectic n={n}")
print(f"[2] M^T J M == J over GF(2) for 75 random Cliffords: {'OK' if fails==before else 'FAILED'}")

# 3. symplectic action agrees with actual conjugation
before=fails
for n in (1,2,3):
    for _ in range(40):
        T=stim.Tableau.random(n); M=clifford_to_symplectic(T,n)
        P=Pauli.from_string("+"+"".join(np.array(list("IXYZ"))[rng.integers(0,4,n)]))
        got=(M@pauli_to_vector(P,n))%2
        want=pauli_to_vector(conjugate(T,P),n)
        chk(np.array_equal(got,want), f"symplectic action != conjugation n={n}")
print(f"[3] M_C * vec(P) == vec(C P C-dagger) for 120 cases: {'OK' if fails==before else 'FAILED'}")

# 4. KNOWN-ANSWER on lu-2022
S=discover_specs("pauliguard/specs")
L=Layer3(S["lu-2022"], QOTP())
certs=L.analyse(n=2, trials=500)
chk(len(certs)>0,"no certificates on lu-2022 (should find the prob-1 forgery)")
print(f"[4] lu-2022: {len(certs)} certificate(s), malleability dimension = "
      f"{certs[0].malleability_dimension if certs else 'n/a'}")
for c in certs[:2]:
    chk(c.success_probability==1.0, f"success prob {c.success_probability} != 1.0")
    chk(c.confirmed_by_execution, "certificate not confirmed by execution")
    chk(c.execution_accepted==c.execution_trials, f"accepted {c.execution_accepted}/{c.execution_trials}")
    chk(c.message_changed==c.execution_trials, f"message changed {c.message_changed}/{c.execution_trials}")
    chk("sound" in c.caveat.lower() and "not complete" in c.caveat.lower(), "caveat missing disclaimer")

# 5. precision 1 by construction
chk(all(c.confirmed_by_execution for c in certs),"unconfirmed certificate returned")
print(f"[5] every certificate confirmed by execution (precision 1 by construction): "
      f"{all(c.confirmed_by_execution for c in certs)}")

# 6. anticommuting instance present
signs=set()
for c in certs: signs|=set(c.commutation_sign_range)
chk(-1 in signs, f"no anticommuting instance; signs={signs}")
print(f"[6] commutation signs observed across key space: {sorted(signs)} -> anticommuting present: {-1 in signs}")

# 7. CONTRAST
L2_=Layer3(S["decoy-bb84-qds"], None)
c2=L2_.analyse(n=2, trials=200)
chk(len(c2)==0,f"decoy scheme returned {len(c2)} certificates, expected 0")
print(f"[7] CONTRAST decoy-bb84-qds -> {len(c2)} certificates (expected 0)")

# THE CERTIFICATE, as the demo would show it
if certs:
    c=certs[0]
    print("\n================ L3 CERTIFICATE (demo artifact) ================")
    print(f" scheme                : {c.scheme}")
    print(f" predicate             : {c.predicate}")
    print(f" malleability dimension: {c.malleability_dimension}")
    print(f" witness U             : {c.witness_pauli}")
    print(f" required V            : {c.signature_pauli}")
    print(f" success probability   : {c.success_probability}  over {c.keys_tested} keys")
    print(f" confirmed by execution: {c.execution_accepted}/{c.execution_trials} accepted, "
          f"{c.message_changed}/{c.execution_trials} message changed")
    print(f" commutation signs     : {c.commutation_sign_range}")
    print(f" caveat                : {c.caveat[:150]}")
    print("================================================================")

print("\n"+("ALL INDEPENDENT T9 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
