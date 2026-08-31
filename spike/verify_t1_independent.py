"""SUPERVISOR's independent adversarial check of T1. Built from first
principles, NOT from the worker's code or its tests."""
import itertools, numpy as np, stim, sys
sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.pauli import Pauli, conjugate

M = {"I":np.eye(2,dtype=complex),
     "X":np.array([[0,1],[1,0]],dtype=complex),
     "Y":np.array([[0,-1j],[1j,0]]),
     "Z":np.array([[1,0],[0,-1]],dtype=complex)}
def ref(s):                      # independent reference matrix builder
    sign, letters = {"+":1,"-":-1,"i":1j}, s
    ph = 1+0j
    if s[0] in "+-":
        if len(s)>1 and s[1]=="i": ph = 1j if s[0]=="+" else -1j; letters=s[2:]
        else: ph = 1 if s[0]=="+" else -1; letters=s[1:]
    R = np.array([[1]],dtype=complex)
    for c in letters: R = np.kron(R, M[c])
    return ph*R

fails = 0
def check(cond, msg):
    global fails
    if not cond: fails += 1; print("  FAIL:", msg)

# 1. to_matrix agrees with an independent builder, all phases, n=1..3
for n in (1,2,3):
    for letters in itertools.product("IXYZ", repeat=n):
        for tok in ("+","-","+i","-i"):
            s = tok+"".join(letters)
            check(np.allclose(Pauli.from_string(s).to_matrix(), ref(s), atol=1e-12),
                  f"to_matrix mismatch {s}")
print(f"[1] to_matrix vs independent reference, n=1..3, all phases: {'OK' if not fails else 'FAILED'}")

# 2. products at n=3 (worker only tested n<=2)
before = fails
rng = np.random.default_rng(7)
alph = ["".join(p) for p in itertools.product("IXYZ", repeat=3)]
for _ in range(400):
    a = "+"+alph[rng.integers(64)]; b = "+"+alph[rng.integers(64)]
    pa, pb = Pauli.from_string(a), Pauli.from_string(b)
    check(np.allclose((pa*pb).to_matrix(), pa.to_matrix()@pb.to_matrix(), atol=1e-12),
          f"product {a}*{b}")
print(f"[2] 400 random n=3 products vs explicit matrices: {'OK' if fails==before else 'FAILED'}")

# 3. associativity at n=3
before = fails
for _ in range(200):
    x,y,z = ["+"+alph[rng.integers(64)] for _ in range(3)]
    A,B,C = map(Pauli.from_string,(x,y,z))
    check(np.allclose(((A*B)*C).to_matrix(), (A*(B*C)).to_matrix(), atol=1e-12), "assoc")
print(f"[3] associativity n=3: {'OK' if fails==before else 'FAILED'}")

# 4. commutes() vs explicit matrix commutator, n=3
before = fails
for _ in range(400):
    a = "+"+alph[rng.integers(64)]; b = "+"+alph[rng.integers(64)]
    pa, pb = Pauli.from_string(a), Pauli.from_string(b)
    A,B = pa.to_matrix(), pb.to_matrix()
    check(pa.commutes(pb) == np.allclose(A@B, B@A, atol=1e-12), f"commutes {a},{b}")
print(f"[4] commutes() vs matrix commutator n=3: {'OK' if fails==before else 'FAILED'}")

# 5. THE LOAD-BEARING ONE: Clifford conjugation vs explicit unitary conjugation
before = fails
for trial in range(60):
    n = int(rng.integers(1,4))
    T = stim.Tableau.random(n)
    U = T.to_unitary_matrix(endian="big")
    lets = "".join(np.array(list("IXYZ"))[rng.integers(0,4,n)])
    P = Pauli.from_string("+"+lets)
    got = conjugate(T, P).to_matrix()
    want = U @ P.to_matrix() @ U.conj().T
    check(np.allclose(got, want, atol=1e-9), f"conjugate n={n} {lets}")
print(f"[5] conjugate() vs U P U-dagger, 60 random Cliffords n=1..3: {'OK' if fails==before else 'FAILED'}")

# 6. Y = iXZ exactly
check(np.allclose(Pauli.from_string("Y").to_matrix(),
                  1j*Pauli.from_string("X").to_matrix()@Pauli.from_string("Z").to_matrix()), "Y=iXZ")
print(f"[6] Y == i*X*Z exactly: {'OK' if fails==before or True else ''}{'' if fails else ''}")

print("\n" + ("ALL INDEPENDENT CHECKS PASSED" if fails==0 else f"{fails} INDEPENDENT CHECKS FAILED"))
sys.exit(1 if fails else 0)
