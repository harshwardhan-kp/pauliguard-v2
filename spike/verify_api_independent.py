"""SUPERVISOR audit of the API -- the product claim must hold over HTTP."""
import sys, json; sys.path.insert(0,"/Users/harshwardhan/Claude/pauliguard-v2")
from fastapi.testclient import TestClient
from pauliguard.api import app
c=TestClient(app); fails=0
def chk(x,m):
    global fails
    if not x: fails+=1; print("   FAIL:",m)

h=c.get("/api/health").json()
print(f"[1] health: {h}")
chk(h.get("status")=="ok","health not ok")
floor=json.load(open("results/floor_ibm_kingston.json"))["error_floor"]
chk(abs(h["floor"]-floor)<1e-15,f"floor {h['floor']} != measured {floor}")

s=c.get("/api/schemes").json()
print(f"[2] schemes: {[x['name'] for x in s]}")
chk(len(s)>=3,"fewer than 3 schemes")
chk(all(x["assumed_fields"] for x in s),"a scheme declares no assumed_fields")

def run(**kw):
    body={"scheme":"lu-2022","n_message_qubits":2,"attack":None,"attack_pauli":"X",
          "noise_p":0.0,"decoy_rounds":400,"alpha":1e-10,"seed":7}
    body.update(kw); r=c.post("/api/run",json=body)
    chk(r.status_code==200,f"run failed {r.status_code}: {r.text[:200]}")
    return r.json()

o=run()
print(f"[3] honest : accepted={o['summary']['accepted']} changed={o['summary']['message_changed']} "
      f"L1={o['layers']['L1']['flagged']} L3={o['layers']['L3']['flagged']}")
chk(o["summary"]["accepted"] and not o["summary"]["message_changed"],"honest run wrong")
chk(not o["layers"]["L1"]["flagged"],"L1 false positive on honest")

a=run(attack="paired_pauli")
L=a["layers"]
print(f"[4] FORGERY: accepted={a['summary']['accepted']} changed={a['summary']['message_changed']} "
      f"L0={L['L0']['flagged']} L1={L['L1']['flagged']} L2={L['L2']['flagged']} L3={L['L3']['flagged']}")
print(f"    Alice sent {a['summary']['message_in']} -> Bob accepted {a['summary']['message_out']}")
# THE PRODUCT CLAIM, over HTTP
chk(a["summary"]["accepted"],"forgery not accepted")
chk(a["summary"]["message_changed"],"message not changed")
chk(not L["L1"]["flagged"],"L1 fired on the invisible forgery -- would contradict the theorem")
chk(not L["L2"]["flagged"],"L2 fired on the invisible forgery")
chk(L["L3"]["flagged"],"L3 failed to fire on the forgery")

i=run(attack="intercept_resend")
print(f"[5] intercept_resend: L1={i['layers']['L1']['flagged']} (must be True)")
chk(i["layers"]["L1"]["flagged"],"L1 missed intercept_resend")

cmp=c.post("/api/compare",json={"scheme":"lu-2022","n_message_qubits":2,"attack_pauli":"X",
      "noise_p":0.0,"decoy_rounds":4000,"alpha":1e-10,"seed":11}).json()
print(f"[6] compare: honest decoy={cmp['decoy_rate_honest']:.5f} forged decoy={cmp['decoy_rate_forged']:.5f} "
      f"both_within_threshold={cmp['both_within_threshold']}")
chk(cmp["both_within_threshold"],"decoy rates distinguishable -- contradicts the claim")

cert=c.get("/api/certificate/lu-2022?n=2").json()
print(f"[7] lu-2022 certificates: {len(cert)}  success_prob={cert[0]['success_probability'] if cert else 'n/a'}")
chk(cert and cert[0]["success_probability"]==1.0,"certificate missing or prob != 1.0")
con=c.get("/api/certificate/decoy-bb84-qds?n=2").json()
print(f"[8] CONTRAST decoy-bb84-qds certificates: {len(con)} (expected 0)")
chk(len(con)==0,"contrast scheme produced certificates")

print("[9] derivations shown in UI:")
for k,v in L.items(): print(f"      {k}: {str(v.get('derivation'))[:95]}")
chk(all(L[k].get("derivation") for k in L),"a layer has an empty derivation string")

r404=c.post("/api/run",json={"scheme":"nope","n_message_qubits":2,"attack":None,
    "attack_pauli":"X","noise_p":0.0,"decoy_rounds":100,"alpha":1e-10,"seed":1})
print(f"[10] unknown scheme -> {r404.status_code} (must be 404, not 500)")
chk(r404.status_code==404,f"got {r404.status_code}")

print("\n"+("ALL INDEPENDENT API CHECKS PASSED" if fails==0 else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
