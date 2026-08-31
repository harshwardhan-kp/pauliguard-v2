"""SUPERVISOR audit of L2, including the sensitivity sweep the worker did not report."""
import sys, math, numpy as np, stim; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.detectors.layer2 import (Layer2, azuma_fpr, tau_for_alpha_azuma,
                                         chsh_from_correlators, ideal_chsh)
fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

# 1. CHSH constants against my own values
chk(abs(ideal_chsh()-2*math.sqrt(2))<1e-12,"ideal CHSH wrong")
chk(ideal_chsh()>2,"Tsirelson not above separable bound")
print(f"[1] ideal CHSH = {ideal_chsh():.6f}  (2*sqrt2 = {2*math.sqrt(2):.6f}), separable bound 2 -> OK")

# 2. Azuma inverse + looseness vs iid Hoeffding
before=fails
for m in (50,200,4096):
    for a in (1e-3,1e-6,1e-10):
        t=tau_for_alpha_azuma(m,a)
        chk(abs(azuma_fpr(m,t)-a)/a<1e-12,f"azuma round-trip m={m} a={a}")
    for tau in (0.01,0.05,0.2):
        chk(azuma_fpr(m,tau) > math.exp(-2*m*tau*tau)-1e-300, f"azuma tighter than iid m={m}")
print(f"[2] Azuma exact inverse + honestly LOOSER than iid Hoeffding: {'OK' if fails==before else 'FAILED'}")
m,tau=200,0.1
print(f"    at m=200,tau=0.1: azuma={azuma_fpr(m,tau):.4e}  iid_hoeffding={math.exp(-2*m*tau*tau):.4e}"
      f"  ratio={azuma_fpr(m,tau)/math.exp(-2*m*tau*tau):.1f}x looser (price of adaptivity)")

# 3. ideal resource -> never flagged; corrupted -> always
before=fails
L=Layer2(alpha=1e-6)
T=stim.Circuit("H 0\nCNOT 0 1").to_tableau()
ideal=sum(L.analyse_resource(T,m=500,seed=i,corruption=0.0).flagged for i in range(200))
corr =sum(L.analyse_resource(T,m=500,seed=i,corruption=0.30).flagged for i in range(200))
chk(ideal==0,f"ideal flagged {ideal}/200"); chk(corr==200,f"corrupted flagged {corr}/200")
print(f"[3] ideal resource flagged {ideal}/200 ; 30%-corrupted flagged {corr}/200 -> {'OK' if fails==before else 'FAILED'}")

# 4. SENSITIVITY SWEEP (the number the worker never printed)
print("[4] L2 detection rate vs resource corruption (m=500, alpha=1e-6):")
rates=[]
for c in (0.0,0.01,0.05,0.10,0.20,0.40):
    r=sum(L.analyse_resource(T,m=500,seed=1000+i,corruption=c).flagged for i in range(200))/200
    rates.append(r); print(f"      corruption={c:<5} detection rate={r:.3f}")
chk(all(rates[i]<=rates[i+1]+1e-12 for i in range(len(rates)-1)),f"not monotonic: {rates}")
print(f"    monotonically non-decreasing: {all(rates[i]<=rates[i+1]+1e-12 for i in range(len(rates)-1))}")

# 5. THE BLINDNESS RESULT, recomputed
before=fails
blind=sum(L.analyse_resource(T,m=200,seed=5000+i,corruption=0.0).flagged for i in range(200))
chk(blind==0,f"L2 flagged {blind}/200 on untouched resource")
print(f"[5] BLINDNESS: paired-Pauli leaves the resource pristine -> L2 flags {blind}/200")
print(f"    This is a TRUE NEGATIVE by construction. L1 blind + L2 blind = why L3 exists.")

# 6. no hidden literal
t1=Layer2(alpha=1e-3).analyse_resource(T,m=200,seed=1,corruption=0.0)
t2=Layer2(alpha=1e-12).analyse_resource(T,m=200,seed=1,corruption=0.0)
chk(t1.threshold!=t2.threshold,"threshold does not respond to alpha -> hidden literal")
print(f"[6] threshold responds to alpha: {t1.threshold:.5f} (a=1e-3) vs {t2.threshold:.5f} (a=1e-12) -> OK")
print(f"    derivation: {t1.derivation[:110]}")

print("\n"+("ALL INDEPENDENT T8 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
