"""SUPERVISOR audit of L1. Recomputes the statistics from the formulas and
re-derives the headline TPR from raw engine runs."""
import sys, math; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.detectors.layer1 import (serfling_fpr, hoeffding_fpr, tau_for_alpha,
                                         clopper_pearson, Layer1)
from pauliguard.engine.spec_loader import discover_specs
from pauliguard.engine.protocol import ProtocolEngine, RunConfig
fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

# 1. formulas match my independent closed forms
for (k,N,tau) in [(4096,16384,0.03),(1000,5000,0.05),(200,900,0.1)]:
    mine=math.exp(-2*k*tau*tau/(1-(k-1)/N))
    chk(abs(serfling_fpr(k,N,tau)-mine)/mine<1e-12,f"serfling mismatch k={k}")
    chk(abs(hoeffding_fpr(k,tau)-math.exp(-2*k*tau*tau))<1e-15,f"hoeffding mismatch k={k}")
print(f"[1] serfling/hoeffding match independent closed forms: {'OK' if not fails else 'FAILED'}")

# 2. Serfling strictly tighter, and converges to Hoeffding as N->inf
before=fails
for k in (100,1000,4096):
    for N in (2*k,4*k,100*k):
        chk(serfling_fpr(k,N,0.03) < hoeffding_fpr(k,0.03), f"not tighter k={k} N={N}")
chk(abs(serfling_fpr(4096,10**9,0.03)-hoeffding_fpr(4096,0.03))/hoeffding_fpr(4096,0.03)<1e-3,"no convergence")
print(f"[2] Serfling strictly tighter for finite N, converges as N->inf: {'OK' if fails==before else 'FAILED'}")

# 3. inversion round-trip
before=fails
for k,N in [(4200,16800),(500,2000)]:
    for a in (1e-3,1e-6,1e-10):
        chk(abs(serfling_fpr(k,N,tau_for_alpha(k,N,a))-a)/a<1e-9,f"round-trip k={k} a={a}")
print(f"[3] tau_for_alpha inverts serfling_fpr exactly: {'OK' if fails==before else 'FAILED'}")

# 4. bound is genuinely an upper bound on the hypergeometric tail
before=fails
from scipy.stats import hypergeom
viol=0; tested=0
for N in (200,400): 
    for k in (20,50):
        for M in (int(0.2*N),int(0.4*N)):
            mu=M/N
            for tau in (0.05,0.1,0.2):
                thr=math.floor((mu+tau)*k)
                true=hypergeom.sf(thr-1,N,M,k) if thr>=1 else 1.0
                b=serfling_fpr(k,N,tau); tested+=1
                if true>b+1e-12: viol+=1
chk(viol==0,f"{viol}/{tested} hypergeometric tail violations")
print(f"[4] Serfling upper-bounds the true hypergeometric tail: {viol}/{tested} violations -> {'OK' if fails==before else 'FAILED'}")

# 5. THE HARDWARE POINT
FLOOR=0.034423828125
print(f"[5] absolute tau=0.03 vs measured floor {FLOOR:.6f}: absolute rule would flag an honest"
      f" run ({FLOOR:.4f} >= 0.03 -> {FLOOR>=0.03}); floor-relative does not.")
chk(FLOOR>0.03,"floor no longer exceeds 0.03")

# 6. THE HEADLINE, recomputed from raw runs
spec=discover_specs("pauliguard/specs")["lu-2022"]; eng=ProtocolEngine(spec)
L=Layer1(alpha=1e-10, floor=FLOOR)
def tpr(attack,noise,N=250,**kw):
    f=0
    for i in range(N):
        t=eng.run(RunConfig(n_message_qubits=2,seed=20000+i,decoy_rounds=400,
                            noise_p=noise,attack=attack,**kw))
        if L.analyse(t).flagged: f+=1
    return f/N
print("[6] L1 detection rates recomputed from raw engine runs (alpha=1e-10):")
row=[]
for noise in (0.0,0.001,0.01,0.05):
    h=tpr(None,noise); a=tpr("paired_pauli",noise,attack_pauli="X")
    row.append((noise,h,a))
    print(f"     noise={noise:<6} honest FPR={h:.4f}   paired_pauli TPR={a:.4f}")
    chk(a==0.0,f"paired_pauli TPR nonzero ({a}) at noise={noise} -- THIS WOULD BE A BUG")
ir=tpr("intercept_resend",0.0)
print(f"     intercept_resend TPR={ir:.4f}  (L1 works where it can work)")
chk(ir==1.0,f"intercept_resend TPR {ir} != 1.0")

# 7. derivation string carries real numbers
v=L.analyse(eng.run(RunConfig(n_message_qubits=2,seed=1,decoy_rounds=400)))
print(f"[7] derivation string: {v.derivation}")
chk(str(v.k) in v.derivation and "Serfling" in v.derivation,"derivation missing numbers/name")
lo,hi=clopper_pearson(0,100); print(f"    clopper_pearson(0,100)={lo:.4f},{hi:.4f} (no NaN)")
chk(not (math.isnan(lo) or math.isnan(hi)),"clopper-pearson NaN at 0 successes")

print("\n"+("ALL INDEPENDENT T7 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
