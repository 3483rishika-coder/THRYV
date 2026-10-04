import json, sys
from .checks import replay
def main(a):
    if len(a) >= 2 and a[0] == "replay":
        target = a[a.index("--target") + 1] if "--target" in a else "http://127.0.0.1:3000"; bad = 0
        for c in json.load(open(a[1])):
            ok, _ = replay(target, c["check"]); st = {True: "STILL REPRODUCES", False: "fixed", None: "INCONCLUSIVE"}[ok]
            print(f"{c['id']}: {st}"); bad += ok is not False
        return 1 if bad else 0
    if a[:1] == ["serve"] or not a:
        import os
        if os.environ.get("THRYV_HOST", "127.0.0.1") not in ("127.0.0.1", "localhost") and not os.environ.get("THRYV_PASSWORD"):
            print("Refusing to listen publicly without THRYV_PASSWORD set."); return 2
        import uvicorn; uvicorn.run("thryv.api:app", host=os.environ.get("THRYV_HOST", "127.0.0.1"), port=int(os.environ.get("PORT") or os.environ.get("THRYV_PORT") or 8000)); return 0
    print("usage: python -m thryv [serve | replay checks.json --target URL]"); return 2
sys.exit(main(sys.argv[1:]))
