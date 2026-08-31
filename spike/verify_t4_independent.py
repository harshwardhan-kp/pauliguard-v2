"""SUPERVISOR check of T4: I build my OWN broken traces and confirm validate()
catches each one. A validator that silently returns [] is worse than none."""
import sys; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.trace import *
from dataclasses import replace
fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

def good():
    return Trace(scheme="t",n_message_qubits=1,run_id="r1",session_id="s1",nonce="n1",
        verifier_set=[Party.BOB],
        keys=[KeyDecl(name="k",bits=4,reuse_policy="single-use")],
        registers=[RegisterDecl(name="R0",qubits=1,owner=Party.ALICE,created_step=0)],
        steps=[Step(index=0,procedure=Procedure.INIT,party=Party.ALICE,action=Action.PREPARE,
                    registers=["R0"],keys_used=["k"]),
               Step(index=1,procedure=Procedure.VERIFY,party=Party.BOB,action=Action.MEASURE,
                    registers=["R0"],decoy_protected=True)],
        measurements=[Measurement(step=1,register="R0",basis="Z",outcome=[0,1,0,1],
                                  expected=[0,1,1,1],is_decoy=True)],
        checks=[Check(step=1,name="eq",passed=True)],
        message_in=[0,1],message_out=[0,1])

g=good()
chk(validate(g)==[], f"valid trace rejected: {validate(g)}")
print(f"[1] valid trace accepted: {'OK' if not fails else 'FAILED'}")

# round-trip must preserve ENUM types, not degrade to str
r=Trace.from_json(g.to_json())
chk(r==g,"round-trip inequality")
chk(isinstance(r.steps[0].procedure,Procedure),"procedure degraded to str on round-trip")
chk(isinstance(r.steps[0].party,Party),"party degraded to str")
chk(isinstance(r.steps[0].action,Action),"action degraded to str")
chk(isinstance(r.registers[0],RegisterDecl),"register degraded to dict")
chk(isinstance(r.measurements[0],Measurement),"measurement degraded to dict")
print(f"[2] JSON round-trip preserves enums+nested dataclasses: {'OK' if not fails else 'FAILED'}")

# my own broken traces
before=fails
cases={}
b=good(); b.steps[1].index=5;                       cases["out-of-order step index"]=b
b=good(); b.steps[0].registers=["GHOST"];           cases["undeclared register"]=b
b=good(); b.steps[0].keys_used=["nokey"];           cases["undeclared key"]=b
b=good(); b.measurements[0].step=99;                cases["measurement -> nonexistent step"]=b
b=good(); b.measurements[0].expected=[0,1];         cases["outcome/expected length mismatch"]=b
b=good(); b.registers[0].consumed_step=0; b.steps[1].registers=["R0"]; cases["register used after consumption"]=b
for name,t in cases.items():
    errs=validate(t)
    chk(len(errs)>0, f"validate() MISSED: {name}")
    print(f"   {'caught ' if errs else 'MISSED '} {name}" + (f"  -> {errs[0][:60]}" if errs else ""))
print(f"[3] validator catches all 6 independently-built defects: {'OK' if fails==before else 'FAILED'}")

# decoy counting
before=fails
e,p=g.decoy_error_rate()
chk((e,p)==(1,4), f"decoy_error_rate got {(e,p)}, expected (1,4)")
chk(g.decoy_error_rate(basis="X")==(0,0), f"basis filter wrong: {g.decoy_error_rate(basis='X')}")
chk(g.message_changed() is False,"message_changed false positive")
print(f"[4] decoy counting + basis filter + message_changed: {'OK' if fails==before else 'FAILED'}")

# validator must not raise on garbage
try:
    validate(Trace()); validate(Trace(steps=[Step(index=3,procedure=Procedure.INIT,party=Party.EVE,action=Action.ABORT)]))
    print("[5] validate() does not raise on malformed input: OK")
except Exception as ex:
    fails+=1; print("[5] validate() RAISED:",type(ex).__name__,ex)

print("\n"+("ALL INDEPENDENT T4 CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
