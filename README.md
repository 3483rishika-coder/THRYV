# THRYV — Threat Hunting, Risk & Intelligence Validation
Local-first security assessment: every finding is a record plus a replayable check. "Confirmed" = reproduced; "fixed" = the same check no longer reproduces.

## Run (one command)
    ./run.sh            # then open http://127.0.0.1:8000
    python -m pytest -q # tests (scope gate, CVSS, redaction, inconclusive retest, ledger)

## Workflow
1. Run World Monitor locally (`npm install && npm run dev`, record `git rev-parse HEAD`).
2. Start tab: enter target + optional repo folder, tick authorization, pick depth.
3. Findings: tool results start as *suspected*; header-style notes are *informational*. Validate manually, add a replayable check, set confidence.
4. Fix on a git branch, put the commit hash on the finding, press **Replay now**. Before/after is shown side by side.
5. Coverage tab (4 states, notes required), then Report (print to PDF), SARIF, replay export.

## CLI / CI
    python -m thryv replay checks.json --target http://127.0.0.1:3000   # exit 1 if any check still reproduces
GitHub Actions: run the app, then the line above in a step; a nonzero exit fails the build.

## Design rules
Scope gate (scheme, DNS-resolved IP, no metadata, no redirects followed) · list-args subprocess, timeouts, output caps · only GET/HEAD/OPTIONS ·
retest with target down = *inconclusive* · missing/failed tool never reads as clean · tamper-evident SHA-256 evidence ledger · CVSS 3.1 separate from additive Priority (max 14) ·
THRYV sends CSP/nosniff, disables /docs. Env: THRYV_LAB_HOSTS, THRYV_PORT, THRYV_DB, THRYV_SEMGREP_CONFIG (local rule dirs work offline).
Windows: use WSL2. Docker ZAP targets host.docker.internal (add it to THRYV_LAB_HOSTS). Tauri/sidecar/authenticated testing are planned, not built.

## Deploying to Render (Docker, all scanners included)
1. `git init && git add . && git commit -m "THRYV"`, create an empty GitHub repo, then `git remote add origin <url> && git push -u origin main`.
2. Render > New > Blueprint > pick the repo. When asked, set THRYV_PASSWORD (login: any username + that password).
3. To scan a deployed target, deploy YOUR OWN copy of World Monitor as a second Render service and put its hostname in THRYV_LAB_HOSTS. A hosted THRYV cannot reach 127.0.0.1 on your laptop.
4. In the app, set Repository folder to `/data/repos/target` (cloned automatically from THRYV_CLONE_URL).
Notes: Starter plan + 2 GB disk are needed (Semgrep memory, persistent database). Never scan worldmonitor.app.
