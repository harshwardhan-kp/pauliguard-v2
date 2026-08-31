"""SUPERVISOR audit of L0. I construct every violation myself."""
import sys, copy; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.spec_loader import discover_specs
from pauliguard.engine.protocol import ProtocolEngine, RunConfig
from pauliguard.engine.trace import Party, Procedure, Trace
from pauliguard.detectors.layer0 import Layer0, SessionLedger, analyse_stream
S=discover_specs("pauliguard/specs"); spec=S["lu-2022"]; eng=ProtocolEngine(spec); fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)
codes=lambda F:{f.code for f in F}
crit =lambda F:{f.code for f in F if f.severity=="critical"}

# 1. FPR zero by construction over many honest runs
L=Layer0(spec, SessionLedger()); tot=0
for i in range(400):
    t=eng.run(RunConfig(n_message_qubits=2,seed=9000+i))
    tot+=len(crit(L.analyse(t)))
chk(tot==0,f"{tot} critical findings on honest runs")
print(f"[1] critical findings across 400 honest runs = {tot}  -> {'OK (FPR 0 by construction)' if tot==0 else 'FAILED'}")

# 2. replay of the identical trace
t=eng.run(RunConfig(n_message_qubits=2,seed=1))
r=analyse_stream(spec,[t,t])
chk("L0.REPLAY_SESSION" not in codes(r[0]),"first run flagged as replay")
chk("L0.REPLAY_SESSION" in codes(r[1]),"replay NOT detected on second submission")
print(f"[2] replay: run1={sorted(codes(r[0])) or 'clean'}  run2={sorted(codes(r[1]))}")

# 3. unauthorized verifier -- I mutate the trace myself
t2=Trace.from_json(t.to_json())
mutated=False
for s in t2.steps:
    if s.procedure==Procedure.VERIFY: s.party=Party.EVE; mutated=True; break
chk(mutated,"no VERIFY step to mutate")
f=Layer0(spec,SessionLedger()).analyse(t2)
chk("L0.UNAUTHORIZED_VERIFIER" in codes(f),f"unauthorized verifier missed; got {sorted(codes(f))}")
print(f"[3] Eve performing VERIFY -> {sorted(codes(f))}")

# 4. step order
t3=Trace.from_json(t.to_json()); t3.steps[2].index=99
f=Layer0(spec,SessionLedger()).analyse(t3)
chk("L0.STEP_ORDER" in codes(f),f"step order missed; got {sorted(codes(f))}")
print(f"[4] corrupted step index -> {sorted(codes(f))}")

# 5. never raises on garbage
try:
    Layer0(spec,SessionLedger()).analyse(Trace()); print("[5] analyse(empty Trace) did not raise: OK")
except Exception as e:
    fails+=1; print("[5] RAISED:",type(e).__name__,e)

# 6. missing-procedure warning across all specs (honesty check on claims)
print("[6] claims vs procedures actually present:")
for nm in sorted(S):
    sp=S[nm]; tt=ProtocolEngine(sp).run(RunConfig(n_message_qubits=2,seed=3))
    f=Layer0(sp,SessionLedger()).analyse(tt)
    mp=[x for x in f if x.code=="L0.MISSING_PROCEDURE"]
    print(f"     {nm:22} claims={len(sp.claims)}  MISSING_PROCEDURE findings={len(mp)}")
    for x in mp: print(f"          warning: {x.message[:95]}")

print("\n"+("ALL INDEPENDENT T6 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
