# Authorization statement
THRYV is used only against an isolated, self-hosted local instance owned by the tester. The scope gate allows loopback addresses
(and hosts listed in `THRYV_LAB_HOSTS`) and blocks public and link-local/cloud-metadata addresses. No scan, request, exploit attempt,
or data access is performed against the production World Monitor deployment (worldmonitor.app). Findings are reported responsibly
(via the project's SECURITY.md) with sensitive evidence redacted. Record commit hash, date and tester names below.

Commit tested: ____  Date: ____  Testers: ____
