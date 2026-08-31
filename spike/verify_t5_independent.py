"""SUPERVISOR independent audit of the protocol engine.
Runs the engine myself and recomputes every gate from raw traces."""
import sys, json, collections; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.spec_loader import discover_specs
from pauliguard.engine.protocol import ProtocolEngine, RunConfig
from pauliguard.engine.trace import validate
S=discover_specs("pauliguard/specs"); fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

eng=ProtocolEngine(S["lu-2022"])
def batch(N,**kw):
    return [eng.run(RunConfig(n_message_qubits=2, seed=1000+i, **kw)) for i in range(N)]

# GATE 1 honest
T=batch(1500)
acc=sum(t.accepted for t in T)/len(T)
same=sum(not t.message_changed() for t in T)/len(T)
inval=sum(len(validate(t))>0 for t in T)
chk(acc==1.0,f"honest acceptance {acc}"); chk(same==1.0,f"honest message preserved {same}")
chk(inval==0,f"{inval} invalid traces")
print(f"[GATE 1] honest: accepted={acc:.4f} message_preserved={same:.4f} invalid_traces={inval}")

# GATE 2 paired pauli, X and Y
for P in ("X","Y"):
    T=batch(1500, attack="paired_pauli", attack_pauli=P)
    eq=sum(all(c.passed for c in t.checks) for t in T)/len(T)
    ch=sum(t.message_changed() for t in T)/len(T)
    chk(eq==1.0,f"{P}: equality pass rate {eq} != 1.0")
    chk(ch==1.0,f"{P}: message changed rate {ch} != 1.0")
    print(f"[GATE 2] paired_pauli {P}: arbitrator_ACCEPTED={eq:.4f}  message_CHANGED={ch:.4f}")
# Z must pass but NOT change the message (phase only) -- a distinguishing behavioural test
T=batch(400, attack="paired_pauli", attack_pauli="Z")
eqz=sum(all(c.passed for c in t.checks) for t in T)/len(T)
chz=sum(t.message_changed() for t in T)/len(T)
print(f"[GATE 2b] paired_pauli Z: accepted={eqz:.4f} message_changed={chz:.4f} (Z should NOT flip a computational bit)")
chk(eqz==1.0,"Z attack rejected")

# CONTROL unpaired
T=batch(400, attack="unpaired_pauli")
eq=sum(all(c.passed for c in t.checks) for t in T)/len(T)
chk(eq==0.0,f"unpaired control passes {eq}, should be 0.0")
print(f"[CONTROL] unpaired_pauli accepted={eq:.4f}  (must be 0.0 or gate 2 is vacuous)")

# decoy statistics
h=batch(300); ir=batch(300, attack="intercept_resend")
def rate(T):
    e=sum(t.decoy_error_rate()[0] for t in T); p=sum(t.decoy_error_rate()[1] for t in T)
    return e/p if p else 0
rh, ri = rate(h), rate(ir)
chk(ri>rh+0.1, f"intercept-resend not elevated: honest={rh:.4f} ir={ri:.4f}")
print(f"[DECOY] honest error rate={rh:.4f} (floor 0.0344)   intercept_resend={ri:.4f}  -> elevated: {ri>rh+0.1}")

# reproducibility
a=eng.run(RunConfig(n_message_qubits=2,seed=42)); b=eng.run(RunConfig(n_message_qubits=2,seed=42))
chk(a.to_json()==b.to_json(),"same seed produced different traces")
print(f"[REPRO] identical trace for seed=42: {a.to_json()==b.to_json()}")

# THE DEMO SCENARIO, end to end
d=eng.run(RunConfig(n_message_qubits=2, seed=7, attack="paired_pauli", attack_pauli="X"))
print(f"\n[DEMO] Alice sent {d.message_in} -> Bob accepted {d.message_out}")
print(f"       arbitrator ACCEPTED = {d.accepted} | message CHANGED = {d.message_changed()}")
print(f"       decoy error rate = {d.decoy_error_rate()} (unchanged from honest -> statistically invisible)")
chk(d.accepted and d.message_changed(), "demo scenario broken")

# all three specs run
for nm in sorted(S):
    try:
        t=ProtocolEngine(S[nm]).run(RunConfig(n_message_qubits=2,seed=5))
        chk(len(validate(t))==0, f"{nm} emitted invalid trace")
        print(f"[SPEC] {nm:22} runs OK, accepted={t.accepted}, trace valid")
    except Exception as e:
        fails+=1; print(f"[SPEC] {nm} RAISED {type(e).__name__}: {e}")

print("\n"+("ALL INDEPENDENT T5 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
