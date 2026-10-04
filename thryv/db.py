import hashlib, os, sqlite3, time
DB = os.environ.get("THRYV_DB", "thryv.db")
SQL = """
create table assessments(id integer primary key, name text, target text, repo text, profile text, commit_hash text, created text, status text, tools text default '{}');
create table findings(id integer primary key, aid integer references assessments(id), fid text, title text, description text, component text, severity text, cvss_vector text, cvss_score real,
 steps text, poc text, business_impact text, remediation text, confidence text, source text, tool_version text, category text, exposure int, impact int, check_json text, validation text,
 fix_diff text, fix_commit text, retest text default 'pending', priority int, dedupe text, created text);
create unique index ux_dedupe on findings(aid, dedupe);
create index ix_find_aid on findings(aid);
create table retests(id integer primary key, finding_id integer references findings(id), ts text, result text, evidence text, commit_hash text);
create table coverage(aid integer, row text, state text, note text, primary key(aid,row));
create table ledger(id integer primary key, ref text, ref_id int, ts text, content_hash text, prev_hash text, hash text);
"""
def sha(s): return hashlib.sha256((s or "").encode()).hexdigest()
def now(): return time.strftime("%Y-%m-%d %H:%M:%S")
def conn():
    c = sqlite3.connect(DB, check_same_thread=False, timeout=15); c.row_factory = sqlite3.Row
    c.execute("pragma journal_mode=wal"); c.execute("pragma foreign_keys=on"); return c
def init():
    c = conn()
    if c.execute("pragma user_version").fetchone()[0] < 1:
        c.executescript(SQL); c.execute("pragma user_version=1")
    c.commit(); c.close()
def q(sql, a=()):
    c = conn(); r = [dict(x) for x in c.execute(sql, a)]; c.close(); return r
def x(sql, a=()):
    c = conn(); cur = c.execute(sql, a); c.commit(); i = cur.lastrowid; c.close(); return i
def ledger(ref, ref_id, content):
    prev = (q("select hash from ledger order by id desc limit 1") or [{"hash": "0" * 64}])[0]["hash"]
    ch = sha(content)
    x("insert into ledger(ref,ref_id,ts,content_hash,prev_hash,hash) values(?,?,?,?,?,?)", (ref, ref_id, now(), ch, prev, sha(prev + ref + str(ref_id) + ch)))
def verify():
    prev, bad = "0" * 64, []
    for r in q("select * from ledger order by id"):
        src = (q("select poc c from findings where id=?", (r["ref_id"],)) if r["ref"] == "poc" else q("select evidence c from retests where id=?", (r["ref_id"],)))
        ok = r["prev_hash"] == prev and r["hash"] == sha(prev + r["ref"] + str(r["ref_id"]) + r["content_hash"]) and bool(src) and sha(src[0]["c"]) == r["content_hash"]
        if not ok: bad.append(r["id"])
        prev = r["hash"]
    return {"ok": not bad, "entries": len(q("select id from ledger")), "tampered_ids": bad}
