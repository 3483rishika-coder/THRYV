"""Safe, read-only HTTP checks and the replayable-check engine."""
import re, urllib.request, urllib.error
from .gate import check_target, ScopeError

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None   # never follow; we only report
_op = urllib.request.build_opener(_NoRedirect)
SAFE = ("GET", "HEAD", "OPTIONS")
_RX = re.compile(r"(?im)^(authorization|cookie|set-cookie|x-api-key)\s*:.*$|eyJ[\w-]{10,}\.[\w-]+\.[\w-]+|\b\w{3,}_[A-Za-z0-9]{20,}\b")

def redact(s): return _RX.sub(lambda m: "[REDACTED]", s or "")[:4000]

def fetch(url, method="GET", headers=None, timeout=8):
    check_target(url)
    if method not in SAFE: raise ScopeError("Only GET/HEAD/OPTIONS are allowed.")
    try: r = _op.open(urllib.request.Request(url, method=method, headers=headers or {}), timeout=timeout)
    except urllib.error.HTTPError as e: r = e
    return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(200000).decode("utf-8", "replace")

def replay(base, chk):
    """Returns (reproduced: True/False/None, evidence). None = inconclusive (target unreachable)."""
    url = base.rstrip("/") + chk.get("path", "/")
    try: st, h, b = fetch(url, chk.get("method", "GET"), chk.get("headers"))
    except ScopeError: raise
    except OSError as e: return None, f"Target unreachable: {e}"
    a = chk.get("assert", {}); ok = True
    if "status" in a: ok &= st == a["status"]
    if "body_contains" in a: ok &= a["body_contains"] in b
    if "header_missing" in a: ok &= a["header_missing"].lower() not in h
    if "header_present" in a: ok &= a["header_present"].lower() in h
    if "header_contains" in a: ok &= a["header_contains"][1] in h.get(a["header_contains"][0].lower(), "")
    ev = f"{chk.get('method','GET')} {url}\nStatus: {st}\n" + "\n".join(f"{k}: {v}" for k, v in list(h.items())[:25]) + "\n\n" + b[:600]
    return bool(ok), redact(ev)

def _f(title, cat, comp, desc, fix, chk, sev="info", conf="informational", imp=1, exp=1, impact=""):
    return dict(title=title, category=cat, component=comp, description=desc, remediation=fix, check_json=chk, severity=sev,
                confidence=conf, impact=imp, exposure=exp, source="thryv-safe-check", business_impact=impact or desc,
                steps="Start the local instance; replay the stored check (see Replayable check).")

def safe_checks(base):
    out, base = [], base.rstrip("/")
    st, h, body = fetch(base + "/")           # raises if unreachable -> scan marked failed
    for name, cat, t in [("content-security-policy", "Client-side controls", "Missing Content-Security-Policy"),
                         ("x-content-type-options", "Client-side controls", "Missing X-Content-Type-Options"),
                         ("x-frame-options", "Client-side controls", "Missing clickjacking protection")]:
        if name not in h and not (name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", "")):
            out.append(_f(t, cat, "GET /", f"Response lacks {name}. Hardening observation; the dev server may omit it while deployment config sets it.",
                          f"Send {name} from the server or reverse proxy.", {"method": "GET", "path": "/", "assert": {"header_missing": name}}))
    if base.startswith("https") and "strict-transport-security" not in h:
        out.append(_f("Missing HSTS", "Secure communication", "GET /", "HTTPS response has no Strict-Transport-Security.", "Add HSTS.",
                      {"method": "GET", "path": "/", "assert": {"header_missing": "strict-transport-security"}}))
    if "http://" in " ".join(re.findall(r'(?:src|href)="(http://[^"]+)"', body)):
        out.append(_f("Insecure http:// resource reference", "Secure communication", "GET /", "Page references http:// resources.", "Use https:// URLs.",
                      {"method": "GET", "path": "/", "assert": {"body_contains": "http://"}}))
    if any("httponly" not in c.lower() for c in [h.get("set-cookie", "")] if c):
        out.append(_f("Cookie without HttpOnly", "Authentication and session", "Set-Cookie on /", "A cookie is set without HttpOnly.", "Add HttpOnly; Secure; SameSite.",
                      {"method": "GET", "path": "/", "assert": {"header_present": "set-cookie"}}))
    try:
        _, ch, _ = fetch(base + "/", headers={"Origin": "https://evil.example"})
        if ch.get("access-control-allow-origin") in ("*", "https://evil.example"):
            out.append(_f("Permissive CORS policy", "API security", "GET /", "Server allows an arbitrary foreign Origin.", "Restrict to an allowlist.",
                          {"method": "GET", "path": "/", "headers": {"Origin": "https://evil.example"}, "assert": {"header_present": "access-control-allow-origin"}}, "low", "confirmed", 2, 2,
                          "Foreign sites could read responses if the endpoint returns non-public data."))
    except OSError: pass
    for src in re.findall(r'<script[^>]+src="(/[^"]+)"', body)[:3]:
        try:
            s, _, mb = fetch(base + src + ".map")
            if s == 200 and '"mappings"' in mb:
                out.append(_f("Source map publicly exposed", "Client-side controls", src + ".map", "Original source is recoverable from the map.", "Do not deploy source maps publicly.",
                              {"method": "GET", "path": src + ".map", "assert": {"status": 200, "body_contains": '"mappings"'}}, "low", "confirmed", 2, 2, "Eases attacker code review."))
        except OSError: pass
    for p in ("/docs", "/openapi.json", "/swagger.json"):
        try:
            s, _, _ = fetch(base + p)
            if s == 200: out.append(_f(f"API documentation exposed at {p}", "API security", "GET " + p, "Public API docs reveal the endpoint inventory.", "Disable or protect docs outside development.",
                                       {"method": "GET", "path": p, "assert": {"status": 200}}))
        except OSError: pass
    try:
        s, eh, eb = fetch(base + "/api/__thryv_probe__")
        if re.search(r"Traceback|node_modules|at \S+ \(.+:\d+:\d+\)", eb):
            out.append(_f("Verbose error output", "API security", "GET /api/__thryv_probe__", "Error response leaks stack/path details.", "Return generic errors.",
                          {"method": "GET", "path": "/api/__thryv_probe__", "assert": {"body_contains": "node_modules"}}, "low", "confirmed", 2, 2))
        if not any(k.startswith(("x-ratelimit", "ratelimit", "retry-after")) for k in eh):
            out.append(_f("No rate-limit headers on API", "API security", "GET /api/*", "No rate-limit signalling observed (not proof of absence).", "Add rate limiting and headers.",
                          {"method": "GET", "path": "/api/__thryv_probe__", "assert": {"header_missing": "x-ratelimit-limit"}}))
    except OSError: pass
    return out
