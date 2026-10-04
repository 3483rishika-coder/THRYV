"""Scope gate: only loopback or explicitly configured lab hosts may be tested."""
import ipaddress, os, socket
from urllib.parse import urlparse

class ScopeError(ValueError): pass

def lab_hosts():
    return {h.strip() for h in os.environ.get("THRYV_LAB_HOSTS", "").split(",") if h.strip()}

def check_target(url):
    u = urlparse(url or "")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ScopeError("Target must be an http(s) URL with a host name.")
    if u.username or u.password:
        raise ScopeError("Credentials inside the URL are not allowed.")
    try:
        ips = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(u.hostname, u.port or 80)}
    except socket.gaierror:
        raise ScopeError("Host does not resolve.")
    for ip in ips:
        if ip.is_link_local:
            raise ScopeError("Link-local / cloud metadata addresses are blocked.")
        if not (ip.is_loopback or u.hostname in lab_hosts()):
            raise ScopeError(f"{u.hostname} is outside the authorized local lab scope (loopback or THRYV_LAB_HOSTS only).")
    return url

def check_repo(path):
    p = os.path.realpath(os.path.expanduser(path or ""))
    if not path or not os.path.isdir(p):
        raise ScopeError("Repository path does not exist or is not a directory.")
    root = os.environ.get("THRYV_REPO_ROOT")
    if root and os.path.commonpath([p, os.path.realpath(root)]) != os.path.realpath(root):
        raise ScopeError(f"Repository must be inside {root} on this server.")
    return p
