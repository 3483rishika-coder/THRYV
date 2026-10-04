import html, json, os, threading
from typing import Literal, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, field_validator
from . import cvss, db, scanners
from .checks import replay, safe_checks, redact
from .gate import ScopeError, check_repo, check_target

PORT = int(os.environ.get("PORT") or os.environ.get("THRYV_PORT") or 8000)
ART = os.environ.get("THRYV_ARTIFACTS", "artifacts")
ROWS = ["Authentication and session", "Authorization and access control", "Input validation", "API security",
        "Client-side controls", "Secure communication", "Data storage and privacy"]
SEV = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CONF = {"confirmed": 3, "suspected": 2, "informational": 1}
Sev = Literal["critical", "high", "medium", "low", "info"]
Conf = Literal["confirmed", "suspected", "informational"]
Cat = Literal["Authentication and session", "Authorization and access control", "Input validation", "API security",
              "Client-side controls", "Secure communication", "Data storage and privacy"]

OWASP = {"Authentication and session": "A07:2021 Identification and Authentication Failures", "Authorization and access control": "A01:2021 Broken Access Control",
         "Input validation": "A03:2021 Injection", "API security": "A05:2021 Security Misconfiguration", "Client-side controls": "A05:2021 Security Misconfiguration",
         "Secure communication": "A02:2021 Cryptographic Failures", "Data storage and privacy": "A02:2021 Cryptographic Failures"}
def _own(rows): return [dict(r, owasp=OWASP.get(r["category"], "")) for r in rows]
def lifecycle(f):
    st = [("Detected", True), ("Triaged", bool(f["validation"]) or f["confidence"] != "suspected"), ("Validated", f["confidence"] == "confirmed"),
          ("Evidence captured", bool(f["poc"])), ("Remediation recorded", bool(f["fix_commit"] or f["fix_diff"])), ("Retest passed", f["retest"] == "not_reproduced")]
    return [{"step": a, "done": b} for a, b in st]
FIX = {"patched": False}
def _fx(body, status=200):
    h = {"X-Fixture": "THRYV practice fixture - not World Monitor"}
    h.update({"Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"} if FIX["patched"] else {"Access-Control-Allow-Origin": "*"})
    return HTMLResponse(body, status, headers=h)

app = FastAPI(title="THRYV", docs_url=None, redoc_url=None, openapi_url=None)
_pub = [h for h in (os.environ.get("THRYV_ALLOWED_HOSTS", "") + "," + os.environ.get("RENDER_EXTERNAL_HOSTNAME", "")).split(",") if h.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"] + [h for h in os.environ.get("THRYV_LAB_HOSTS", "").split(",") if h] + _pub)

import base64, secrets
@app.middleware("http")
async def password_gate(req: Request, nxt):
    pw = os.environ.get("THRYV_PASSWORD")
    if pw and req.url.path != "/healthz" and not req.url.path.startswith("/fixture"):
        ok = False
        try:
            u, _, given = base64.b64decode(req.headers.get("authorization", "")[6:]).decode().partition(":")
            ok = secrets.compare_digest(given, pw)
        except Exception: pass
        if not ok: return JSONResponse({"detail": "Login required"}, 401, headers={"WWW-Authenticate": 'Basic realm="THRYV"'})
    return await nxt(req)
db.init()

@app.middleware("http")
async def hardening(req: Request, nxt):
    r = await nxt(req)
    if req.url.path.startswith("/fixture"): return r
    r.headers.update({"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                      "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
    return r

class AssessIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    target: str
    repo: Optional[str] = ""
    profile: Literal["quick", "standard", "deep"] = "quick"
    authorized: bool = False

class FindingIn(BaseModel):
    aid: int
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    component: str = ""
    severity: Sev = "low"
    cvss_vector: Optional[str] = ""
    steps: str = ""
    poc: str = ""
    business_impact: str = ""
    remediation: str = ""
    category: Cat = "API security"
    exposure: int = Field(2, ge=1, le=3)
    impact: int = Field(2, ge=1, le=3)
    check_json: Optional[dict] = None

class PatchIn(BaseModel):
    confidence: Optional[Conf] = None
    validation: Optional[str] = None
    fix_diff: Optional[str] = None
    fix_commit: Optional[str] = None
    remediation: Optional[str] = None

class CovIn(BaseModel):
    aid: int
    row: Cat
    state: Literal["tested-passed", "not-tested", "na"]
    note: str = ""
    @field_validator("note")
    @classmethod
    def _n(cls, v, info): return v

def _one(sql, a):
    r = db.q(sql, a)
    if not r: raise HTTPException(404, "Not found")
    return r[0]

def priority(sev, conf, exp, imp): return SEV.get(sev, 1) + CONF.get(conf, 1) + exp + imp   # additive, max 14

def add_finding(aid, d):
    d = dict(d)
    if d.get("cvss_vector"):
        try: d["cvss_score"] = cvss.score(d["cvss_vector"]); d["severity"] = cvss.severity(d["cvss_score"])
        except ValueError as e: raise HTTPException(400, str(e))
    n = db.q("select count(*) c from findings where aid=?", (aid,))[0]["c"] + 1
    conf, sev = d.get("confidence", "suspected"), d.get("severity", "low")
    v = (aid, f"TH-{n:03d}", d["title"][:200], d.get("description", ""), d.get("component", ""), sev, d.get("cvss_vector") or "", d.get("cvss_score"), d.get("steps", ""), d.get("poc", ""),
         d.get("business_impact", ""), d.get("remediation", ""), conf, d.get("source", "manual"), d.get("tool_version", ""), d.get("category", "Input validation"), d.get("exposure", 2), d.get("impact", 2),
         json.dumps(d["check_json"]) if d.get("check_json") else "", d.get("validation", ""), priority(sev, conf, d.get("exposure", 2), d.get("impact", 2)),
         d.get("dedupe") or f"{d['title']}|{d.get('component','')}", db.now())
    c = db.conn()
    try:
        cur = c.execute("insert or ignore into findings(aid,fid,title,description,component,severity,cvss_vector,cvss_score,steps,poc,business_impact,remediation,confidence,source,tool_version,category,exposure,impact,check_json,validation,priority,dedupe,created) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", v)
        c.commit(); fid = cur.lastrowid if cur.rowcount else None
    finally: c.close()
    if fid and d.get("poc"): db.ledger("poc", fid, d["poc"])
    return fid

def _tools(aid, t): db.x("update assessments set tools=? where id=?", (json.dumps(t), aid))

def run_scan(aid):
    a = _one("select * from assessments where id=?", (aid,)); art = os.path.join(ART, str(aid)); os.makedirs(art, exist_ok=True)
    tools = {"safe-checks": {"state": "running"}}
    for t in ("npm-audit", "semgrep", "gitleaks"): tools[t] = {"state": "skipped", "detail": "not in this profile"}
    _tools(aid, tools); to = 1800 if a["profile"] == "deep" else 600
    try:
        for f in safe_checks(a["target"]): add_finding(aid, f)
        tools["safe-checks"] = {"state": "done"}
    except Exception as e: tools["safe-checks"] = {"state": "failed", "detail": str(e)[:200]}
    _tools(aid, tools)
    plan = [] if not a["repo"] or a["profile"] == "quick" else [("npm-audit", scanners.npm_audit), ("semgrep", scanners.semgrep)] + ([("gitleaks", scanners.gitleaks)] if a["profile"] == "deep" else [])
    for name, fn in plan:
        tools[name] = {"state": "running"}; _tools(aid, tools)
        try: st, fs, det = fn(a["repo"], art, to)
        except Exception as e: st, fs, det = "failed", [], str(e)[:200]
        for f in fs: add_finding(aid, f)
        tools[name] = {"state": st, "detail": det}; _tools(aid, tools)
    db.x("update assessments set status='finished' where id=?", (aid,))

@app.post("/api/assessments")
def create(a: AssessIn):
    if not a.authorized: raise HTTPException(400, "Tick the authorization box: testing is limited to your own local instance.")
    try:
        check_target(a.target); repo = check_repo(a.repo) if a.repo else ""
    except ScopeError as e: raise HTTPException(403, str(e))
    commit = ""
    if repo:
        try: commit = scanners.run(["git", "-C", repo, "rev-parse", "HEAD"], timeout=10)[1].strip()
        except Exception: pass
    aid = db.x("insert into assessments(name,target,repo,profile,commit_hash,created,status) values(?,?,?,?,?,?,?)", (a.name, a.target, repo, a.profile, commit, db.now(), "running"))
    threading.Thread(target=run_scan, args=(aid,), daemon=True).start()
    return {"id": aid}

@app.get("/healthz")
def healthz(): return {"ok": True}

@app.get("/api/assessments")
def alist(): return db.q("select * from assessments order by id desc")

@app.get("/api/assessments/{aid}")
def aget(aid: int):
    a = _one("select * from assessments where id=?", (aid,)); a["tools"] = json.loads(a["tools"] or "{}"); return a

@app.get("/api/findings")
def flist(aid: int): return _own(db.q("select id,fid,title,severity,cvss_score,confidence,category,component,source,retest,priority from findings where aid=? order by priority desc,id", (aid,)))

@app.get("/api/findings/{fid}")
def fget(fid: int):
    f = _one("select * from findings where id=?", (fid,)); f["retests"] = db.q("select * from retests where finding_id=? order by id", (fid,))
    f["check"] = json.loads(f["check_json"]) if f["check_json"] else None
    f["target"] = _one("select target from assessments where id=?", (f["aid"],))["target"]
    f["lifecycle"] = lifecycle(f); f["owasp"] = OWASP.get(f["category"], "")
    f["priority_explained"] = f"Priority {f['priority']}/14 = severity {SEV.get(f['severity'],1)} + confidence {CONF.get(f['confidence'],1)} + exposure {f['exposure']} + impact {f['impact']}. Internal ranking, not CVSS."
    return f

@app.post("/api/findings")
def fadd(f: FindingIn):
    a = _one("select * from assessments where id=?", (f.aid,)); d = f.model_dump(); d["confidence"] = "suspected"
    if f.check_json:
        try: ok, ev = replay(a["target"], f.check_json)
        except ScopeError as e: raise HTTPException(403, str(e))
        if ok: d["confidence"] = "confirmed"; d["poc"] = d["poc"] or ev
        d["validation"] = "Auto-validated by replayable check." if ok else "Check did not reproduce." if ok is False else "Target unreachable; inconclusive."
    fid = add_finding(f.aid, d)
    if not fid: raise HTTPException(409, "Duplicate finding.")
    return {"id": fid}

@app.patch("/api/findings/{fid}")
def fpatch(fid: int, p: PatchIn):
    _one("select id from findings where id=?", (fid,)); d = {k: v for k, v in p.model_dump().items() if v is not None}
    if "validation" in d: d["validation"] = f"{db.now()}: {d['validation']}"
    for k, v in d.items(): db.x(f"update findings set {k}=? where id=?", (v, fid))
    if "confidence" in d:
        f = _one("select * from findings where id=?", (fid,)); db.x("update findings set priority=? where id=?", (priority(f["severity"], f["confidence"], f["exposure"], f["impact"]), fid))
    return {"ok": True}

@app.post("/api/findings/{fid}/retest")
def retest(fid: int):
    f = _one("select * from findings where id=?", (fid,))
    if not f["check_json"]: raise HTTPException(400, "This finding has no replayable check (tool-detected). Add one to enable retest.")
    a = _one("select * from assessments where id=?", (f["aid"],))
    try: ok, ev = replay(a["target"], json.loads(f["check_json"]))
    except ScopeError as e: raise HTTPException(403, str(e))
    res = "inconclusive" if ok is None else "reproduced" if ok else "not_reproduced"
    rid = db.x("insert into retests(finding_id,ts,result,evidence,commit_hash) values(?,?,?,?,?)", (fid, db.now(), res, ev, f["fix_commit"] or ""))
    db.ledger("retest", rid, ev)
    if res == "reproduced" and not f["poc"]: db.x("update findings set poc=? where id=?", (ev, fid)); db.ledger("poc", fid, ev)
    db.x("update findings set retest=? where id=?", (res, fid)); return {"result": res}

@app.get("/api/coverage")
def coverage(aid: int):
    man = {r["row"]: r for r in db.q("select * from coverage where aid=?", (aid,))}; out = []
    for r in ROWS:
        fs = db.q("select fid from findings where aid=? and category=? and confidence!='informational'", (aid, r))
        m = man.get(r)
        out.append({"row": r, "state": "finding" if fs else (m["state"] if m else "not-tested"), "note": (m or {}).get("note", ""), "findings": [x["fid"] for x in fs]})
    return out

@app.put("/api/coverage")
def cov_put(c: CovIn):
    if c.state != "not-tested" and not c.note.strip(): raise HTTPException(400, "A note explaining the reason is required for 'tested-passed' and 'N/A'.")
    db.x("insert or replace into coverage(aid,row,state,note) values(?,?,?,?)", (c.aid, c.row, c.state, c.note)); return {"ok": True}

@app.get("/api/ledger/verify")
def lverify(): return db.verify()

@app.get("/api/checks/{aid}")
def checks_export(aid: int):
    return [{"id": f["fid"], "title": f["title"], "check": json.loads(f["check_json"])} for f in db.q("select * from findings where aid=? and check_json!='' and confidence='confirmed'", (aid,))]

@app.get("/api/sarif/{aid}")
def sarif(aid: int):
    lv = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rs = [{"ruleId": f["source"], "level": lv[f["severity"]], "message": {"text": f"{f['title']} [{f['confidence']}]"},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["component"] or "n/a"}}}]} for f in db.q("select * from findings where aid=?", (aid,))]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "THRYV"}}, "results": rs}]}

@app.post("/api/selfcheck")
def selfcheck():
    return [{"title": f["title"], "category": f["category"]} for f in safe_checks(f"http://127.0.0.1:{PORT}")]

@app.get("/api/report/{aid}", response_class=HTMLResponse)
def report(aid: int):
    a = aget(aid); E = lambda s: html.escape(str(s if s is not None else ""))
    fs = db.q("select * from findings where aid=? order by priority desc", (aid,)); conf = [f for f in fs if f["confidence"] == "confirmed"]
    sus = [f for f in fs if f["confidence"] == "suspected"]; info = [f for f in fs if f["confidence"] == "informational"]
    tl = "".join(f"<li><b>{E(k)}</b>: {E(v.get('state'))} {E(v.get('detail',''))}</li>" for k, v in a["tools"].items())
    def card(f):
        rt = db.q("select * from retests where finding_id=? order by id", (f["id"],)); last = rt[-1] if rt else None
        ba = f"<h4>Before / after</h4><pre>BEFORE (PoC)\n{E(f['poc'])}</pre><pre>AFTER ({E(last['result'])}, commit {E(last['commit_hash'] or 'n/a')})\n{E(last['evidence'])}</pre>" if last else ""
        return (f"<section><h3>{E(f['fid'])} — {E(f['title'])}</h3><p><b>Severity:</b> {E(f['severity'])} · <b>CVSS:</b> {E(f['cvss_score'] or 'not scored')} {E(f['cvss_vector'])} · <b>Confidence:</b> {E(f['confidence'])} · <b>Retest:</b> {E(f['retest'])}</p>"
                f"<p><b>Affected component:</b> {E(f['component'])} · <b>OWASP (suggested):</b> {E(OWASP.get(f['category'],''))}</p><p><b>Description:</b> {E(f['description'])}</p><p><b>Steps to reproduce:</b> {E(f['steps'])}</p><h4>Proof of concept</h4><pre>{E(f['poc'])}</pre>"
                f"<p><b>Business impact:</b> {E(f['business_impact'])}</p><p><b>Remediation:</b> {E(f['remediation'])}</p>{ba}</section>")
    cov = "".join(f"<tr><td>{E(c['row'])}</td><td>{E(c['state'])}</td><td>{E(c['note'])}</td></tr>" for c in coverage(aid))
    return HTMLResponse(f"""<!doctype html><meta charset=utf-8><title>THRYV report</title><style>body{{font:15px/1.5 Georgia,serif;max-width:820px;margin:2em auto;padding:0 1em}}pre{{background:#f4f4f2;padding:8px;white-space:pre-wrap;word-break:break-word}}
td,th{{border:1px solid #bbb;padding:4px 8px;text-align:left}}table{{border-collapse:collapse}}section{{border-top:1px solid #ccc;margin-top:1em;break-inside:avoid}}@media print{{body{{margin:0}}}}</style>
<h1>THRYV assessment report</h1><p><b>{E(a['name'])}</b><br>Target: {E(a['target'])} (local authorized instance only)<br>Commit: {E(a['commit_hash'] or 'n/a')} · Profile: {E(a['profile'])} · {E(a['created'])}</p>
<p><i>All testing was performed against an isolated, self-hosted local instance. No production system was scanned. A tool reporting nothing is not evidence of security.</i></p>
<h2>Tool status</h2><ul>{tl}</ul><h2>Summary</h2><p>{len(fs)} findings: {len(conf)} confirmed, {len(sus)} suspected, {len(info)} informational hardening observations.</p>
<h2>Confirmed findings</h2>{''.join(map(card, conf)) or '<p>None confirmed.</p>'}<h2>Suspected (needs manual validation)</h2><ul>{''.join(f"<li>{E(f['fid'])} {E(f['title'])} ({E(f['component'])})</li>" for f in sus)}</ul>
<h2>Hardening observations</h2><ul>{''.join(f"<li>{E(f['title'])} — {E(f['component'])}</li>" for f in info)}</ul><h2>Scope coverage</h2><table><tr><th>Area</th><th>State</th><th>Note</th></tr>{cov}</table>""")

@app.get("/healthz")
def healthz(): return {"ok": True}

@app.get("/api/info")
def info(): return {"fixture_url": f"http://127.0.0.1:{PORT}/fixture", "hosted": bool(os.environ.get("RENDER"))}

@app.get("/fixture/")
def fx_home(): return _fx("<h1>THRYV practice fixture</h1><p>A deliberately weak page for practising THRYV. It is not World Monitor.</p>")

@app.get("/fixture/api/{rest:path}")
def fx_api(rest: str): return _fx("Not found" if FIX["patched"] else "Error: ENOENT\n    at readFile (/srv/node_modules/app/index.js:12:5)\n    at handler (/srv/node_modules/app/api.js:40:9)", 404)

@app.post("/fixture/_patch")
def fx_patch(): FIX["patched"] = True; return {"patched": True}

@app.post("/fixture/_reset")
def fx_reset(): FIX["patched"] = False; return {"patched": False}

@app.exception_handler(Exception)
async def boom(_, e): return JSONResponse({"detail": "Internal error. Check the server log."}, 500)

@app.get("/")
def index(): return FileResponse(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"))
