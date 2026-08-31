"""SUPERVISOR audit: are the dispute findings REAL, or does the analyser just fire on everything?"""
import sys, tempfile, pathlib, yaml; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from pauliguard.engine.spec_loader import discover_specs, load_spec
from pauliguard.attacks.repudiation import DisputeAnalyser, threat_model_gap_table
S=discover_specs("pauliguard/specs"); fails=0
def chk(c,m):
    global fails
    if not c: fails+=1; print("   FAIL:",m)

print("[1] findings on the three real specs:")
for nm in sorted(S):
    f=DisputeAnalyser(S[nm]).analyse()
    crit=[x for x in f if x.severity=="critical"]
    print(f"   {nm:22} {len(f)} finding(s), {len(crit)} critical")
    for x in f: print(f"       {x.code:34} threat={x.threat:26} claimed={x.claimed_by_scheme}")

# 2. CONTROL: a fully-specified scheme must produce NO critical findings.
# Build one myself: claims both goals, has bound PROOF_OF_ORIGIN and PROOF_OF_RECEIPT,
# Trent verifies before Bob measures, and Trent appears in both dispute procedures.
good={"name":"control-good","citation":"synthetic control","family":"teleportation-aqs",
 "n_message_qubits":2,"encryption":"qotp","verifier_set":["Bob","Trent"],
 "keys":[{"name":"k","bits":4,"reuse_policy":"single-use"}],
 "registers":[{"name":"msg","qubits":2,"owner":"Alice"},{"name":"sig","qubits":2,"owner":"Alice"}],
 "claims":["non_repudiation_origin","non_repudiation_receipt"],
 "assumed_fields":["synthetic"],
 "steps":[
   {"procedure":"INIT","party":"Trent","action":"prepare","registers":["msg"],"keys_used":[],"decoy_protected":False},
   {"procedure":"SIGN","party":"Alice","action":"apply","registers":["msg","sig"],"keys_used":["k"],"decoy_protected":False},
   {"procedure":"VERIFY","party":"Trent","action":"check","registers":["sig","msg"],"keys_used":["k"],"decoy_protected":False},
   {"procedure":"VERIFY","party":"Bob","action":"measure","registers":["msg"],"keys_used":[],"decoy_protected":False},
   {"procedure":"PROOF_OF_ORIGIN","party":"Trent","action":"check","registers":["msg","sig"],"keys_used":["k"],"decoy_protected":False},
   {"procedure":"PROOF_OF_RECEIPT","party":"Trent","action":"check","registers":["msg","sig"],"keys_used":["k"],"decoy_protected":False},
 ]}
d=tempfile.mkdtemp(); p=pathlib.Path(d)/"control-good.yaml"; p.write_text(yaml.safe_dump(good))
gf=DisputeAnalyser(load_spec(str(p))).analyse()
gcrit=[x for x in gf if x.severity=="critical"]
chk(len(gcrit)==0,f"CONTROL well-specified scheme wrongly flagged: {[x.code for x in gcrit]}")
print(f"\n[2] CONTROL well-specified scheme -> {len(gcrit)} critical findings (must be 0) "
      f"{'OK - analyser is not vacuous' if not gcrit else 'FAILED'}")

# 3. each defect I inject must be caught individually
def mutate(fn,name):
    g=yaml.safe_load(yaml.safe_dump(good)); fn(g)
    q=pathlib.Path(d)/f"{name}.yaml"; g["name"]=name; q.write_text(yaml.safe_dump(g))
    return {x.code for x in DisputeAnalyser(load_spec(str(q))).analyse()}
c1=mutate(lambda g: g["steps"].__delitem__(5), "no-receipt")
chk("DR.RECEIPT_NO_PROCEDURE" in c1, f"missing receipt not caught: {c1}")
c2=mutate(lambda g: g["steps"][5].update({"registers":["sig"]}), "unbound-receipt")
chk("DR.RECEIPT_UNBOUND" in c2 and "DR.FALSE_ALLEGATION" in c2, f"unbound receipt: {c2}")
c3=mutate(lambda g: g["steps"].insert(2,{"procedure":"VERIFY","party":"Bob","action":"measure",
          "registers":["msg"],"keys_used":[],"decoy_protected":False}), "early-plaintext")
chk("DR.PLAINTEXT_BEFORE_ARBITRATION" in c3, f"early plaintext not caught: {c3}")
c4=mutate(lambda g: g["steps"].__delitem__(4), "no-origin")
chk("DR.ORIGIN_NO_PROCEDURE" in c4, f"missing origin not caught: {c4}")
print(f"[3] injected defects caught individually:")
for n,cc,want in [("no PROOF_OF_RECEIPT",c1,"DR.RECEIPT_NO_PROCEDURE"),
                  ("receipt unbound from message",c2,"DR.FALSE_ALLEGATION"),
                  ("Bob reads plaintext pre-arbitration",c3,"DR.PLAINTEXT_BEFORE_ARBITRATION"),
                  ("no PROOF_OF_ORIGIN",c4,"DR.ORIGIN_NO_PROCEDURE")]:
    print(f"      {'caught ' if want in cc else 'MISSED '} {n}")

# 4. gap table
g=threat_model_gap_table(S)
for t in ("Repudiation of Origin","Repudiation of Receipt","False Allegation"):
    chk(t.lower() in g.lower(), f"gap table missing {t}")
chk("named by sih26141" in g.lower(),"gap table missing the SIH26141 column")
print(f"[4] threat-model gap table contains all three omitted threats: OK ({len(g)} chars)")

print("\n"+("ALL INDEPENDENT REPUDIATION CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
