"""Scanner runners: list-args, shell=False, timeouts, output caps. Missing tool => 'unavailable', never 'clean'."""
import json, os, shutil, subprocess

def run(cmd, cwd=None, timeout=600):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=False)
    return p.returncode, p.stdout[:5_000_000], p.stderr[:20000]

def _ver(tool):
    try: return run([tool, "--version"], timeout=20)[1].strip().splitlines()[0]
    except Exception: return ""

def semgrep(repo, art, timeout):
    if not shutil.which("semgrep"): return "unavailable", [], "semgrep not installed"
    cfg = os.environ.get("THRYV_SEMGREP_CONFIG", "p/javascript p/typescript p/owasp-top-ten").split()
    cmd = ["semgrep", "scan", "--metrics=off", "--json", "-o", f"{art}/semgrep.json"] + [a for c in cfg for a in ("--config", c)] + [repo]
    rc, _, err = run(cmd, timeout=timeout)
    if rc >= 2 or not os.path.exists(f"{art}/semgrep.json"): return "failed", [], f"exit {rc}: {err[:300]}"
    out, v = [], _ver("semgrep")
    for r in json.load(open(f"{art}/semgrep.json")).get("results", []):
        sev = {"ERROR": "medium", "WARNING": "low"}.get(r["extra"].get("severity"), "info")
        loc = f"{os.path.relpath(r['path'], repo)}:{r['start']['line']}"
        out.append(dict(title=r["check_id"].split(".")[-1], category="Input validation", component=loc, severity=sev, confidence="suspected", source="semgrep",
                        tool_version=v, description=r["extra"].get("message", ""), steps="Review the flagged code and trace whether untrusted input reaches it.",
                        business_impact="Unvalidated: depends on reachability.", remediation="See rule guidance; add a regression test.", poc=r["extra"].get("lines", "")[:500],
                        dedupe=f"semgrep|{r['check_id']}|{loc}"))
    return "done", out, f"{len(out)} results"

def npm_audit(repo, art, timeout):
    if not shutil.which("npm"): return "unavailable", [], "npm not installed"
    if not os.path.exists(os.path.join(repo, "package-lock.json")): return "failed", [], "no package-lock.json; npm audit cannot run"
    rc, o, err = run(["npm", "audit", "--json"], cwd=repo, timeout=timeout)   # nonzero exit = advisories, not failure
    open(f"{art}/npm-audit.json", "w").write(o)
    try: j = json.loads(o)
    except ValueError: return "failed", [], f"unparseable output: {err[:200]}"
    if "error" in j: return "failed", [], str(j["error"])[:300]
    out = []
    for n, v in (j.get("vulnerabilities") or {}).items():
        sev = v.get("severity", "low"); sev = sev if sev in ("critical", "high", "medium", "low") else "info"
        out.append(dict(title=f"Vulnerable dependency: {n}", category="Input validation", component=f"package {n}", severity=sev, confidence="suspected", source="npm-audit",
                        description=f"Direct: {v.get('isDirect')}. Fix available: {bool(v.get('fixAvailable'))}. Reachability NOT assessed.", steps="Check whether the vulnerable code path is used at runtime.",
                        business_impact="Only exploitable if reachable.", remediation="Upgrade per npm audit fix; re-run audit.", dedupe=f"npm|{n}"))
    return "done", out, f"{len(out)} advisories"

def gitleaks(repo, art, timeout):
    if not shutil.which("gitleaks"): return "unavailable", [], "gitleaks not installed"
    rc, _, err = run(["gitleaks", "detect", "--source", repo, "--redact", "--report-format", "json", "--report-path", f"{art}/gitleaks.json"], timeout=timeout)
    if rc > 1: return "failed", [], err[:300]
    try: items = json.load(open(f"{art}/gitleaks.json")) or []
    except (OSError, ValueError): items = []
    out = [dict(title=f"Secret-like value: {i.get('RuleID')}", category="Data storage and privacy", component=f"{i.get('File')}:{i.get('StartLine')}", severity="medium", confidence="suspected",
                source="gitleaks", description="Possible committed secret (value redacted).", steps="Confirm whether the value is a real credential.", business_impact="Credential exposure.",
                remediation="Rotate and remove from history.", dedupe=f"gl|{i.get('RuleID')}|{i.get('File')}|{i.get('StartLine')}") for i in items]
    return "done", out, f"{len(out)} potential secrets"
