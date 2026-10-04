import pytest, os, tempfile
os.environ["THRYV_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
from thryv import cvss, db
from thryv.gate import check_target, ScopeError
from thryv.checks import redact, replay

@pytest.mark.parametrize("u", ["http://127.0.0.1:3000", "http://localhost:3000"])
def test_allow(u): assert check_target(u)
@pytest.mark.parametrize("u", ["http://8.8.8.8", "http://169.254.169.254/latest", "ftp://127.0.0.1", "http://u:p@127.0.0.1", "http://10.0.0.5"])
def test_block(u):
    with pytest.raises(ScopeError): check_target(u)
def test_lab_host(monkeypatch):
    monkeypatch.setenv("THRYV_LAB_HOSTS", "10.0.0.5"); assert check_target("http://10.0.0.5")
def test_cvss():
    assert cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") == 5.3
    assert cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    with pytest.raises(ValueError): cvss.score("garbage")
def test_redact(): assert "abc" not in redact("Authorization: Bearer abc\nx=1")
def test_retest_server_down_is_inconclusive():
    assert replay("http://127.0.0.1:1", {"path": "/", "assert": {"status": 200}})[0] is None
def test_ledger_tamper():
    db.init(); aid = db.x("insert into assessments(name) values('t')")
    fid = db.x("insert into findings(aid,fid,title,poc,dedupe) values(?,?,?,?,?)", (aid, "TH-001", "t", "evidence", "d"))
    db.ledger("poc", fid, "evidence"); assert db.verify()["ok"]
    db.x("update findings set poc='forged' where id=?", (fid,)); assert not db.verify()["ok"]

def test_auth_and_health(monkeypatch):
    monkeypatch.setenv("THRYV_PASSWORD", "s3cret")
    from fastapi.testclient import TestClient
    from thryv.api import app
    c = TestClient(app)
    assert c.get("/healthz").status_code == 200
    assert c.get("/api/assessments").status_code == 401
    assert c.get("/api/assessments", auth=("x", "wrong")).status_code == 401
    assert c.get("/api/assessments", auth=("x", "s3cret")).status_code == 200

def test_repo_root(monkeypatch, tmp_path):
    from thryv.gate import check_repo
    (tmp_path / "ok").mkdir(); monkeypatch.setenv("THRYV_REPO_ROOT", str(tmp_path))
    assert check_repo(str(tmp_path / "ok"))
    with pytest.raises(ScopeError): check_repo("/tmp")
