"""CVSS v3.1 base score calculator (validated against first.org reference values)."""
import math, re
_V = re.compile(r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]")
def _up(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0
def score(vec):
    if not _V.fullmatch(vec or ""):
        raise ValueError("Invalid CVSS 3.x vector. Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    d = dict(p.split(":") for p in vec.split("/")[1:])
    ch = d["S"] == "C"
    w = {"N": .85, "A": .62, "L": .55, "P": .2}[d["AV"]]
    pr = {"N": .85, "L": .68 if ch else .62, "H": .5 if ch else .27}[d["PR"]]
    cia = {"H": .56, "L": .22, "N": 0}
    iss = 1 - (1 - cia[d["C"]]) * (1 - cia[d["I"]]) * (1 - cia[d["A"]])
    imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if ch else 6.42 * iss
    ex = 8.22 * w * {"L": .77, "H": .44}[d["AC"]] * pr * {"N": .85, "R": .62}[d["UI"]]
    if imp <= 0: return 0.0
    return _up(min((1.08 if ch else 1) * (imp + ex), 10))
def severity(s):
    return "info" if s == 0 else "low" if s < 4 else "medium" if s < 7 else "high" if s < 9 else "critical"
