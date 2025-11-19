from urllib.parse import urlsplit, urlunsplit, unquote
import ipaddress
import tldextract

def normalize_url(u: str) -> str:
    if not isinstance(u, str):
        return ""
    u = u.strip().replace("\\\\", "/")
    if not u:
        return ""
    parts = urlsplit(u)
    scheme = (parts.scheme or "http").lower()
    netloc = (parts.netloc or "").lower()
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    if netloc.startswith("www."):
        netloc = netloc[4:]
    path = unquote(parts.path or "")
    query = unquote(parts.query or "")
    return urlunsplit((scheme, netloc, path, query, ""))

def host_parts(u: str):
    netloc = urlsplit(u).netloc
    ext = tldextract.extract(netloc)
    return ext.subdomain, ext.domain, ext.suffix

def is_ip_literal(host: str) -> bool:
    try:
        if ":" in host:
            host = host.split(":")[0]
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False
