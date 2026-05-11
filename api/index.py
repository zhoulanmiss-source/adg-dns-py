import base64
import os
import re
import time
import threading
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen

# =========================
# 配置
# =========================

UPSTREAMS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
RULE_DIR = os.path.join(PROJECT_ROOT, "rule")

ALLOWLIST_PATH = os.path.join(RULE_DIR, "allowlists.txt")
BLOCKLIST_PATH = os.path.join(RULE_DIR, "blocklists.txt")

ALLOWLIST_ONLY = False
UPSTREAM_TIMEOUT = 6

# 缓存配置（限制 TTL 上限）
CACHE_TTL_MAX = 600
DEFAULT_POSITIVE_TTL = 600
NEGATIVE_TTL = 600
CACHE_MAX_ENTRIES = 10000

# =========================
# 工具函数
# =========================

def _normalize_domain(d: str) -> str:
    return d.strip().lower().rstrip(".")


def _is_in_list_with_subdomain(domain: str, rules: frozenset) -> bool:
    d = _normalize_domain(domain)
    while True:
        if d in rules:
            return True
        dot = d.find(".")
        if dot < 0:
            return False
        d = d[dot + 1:]


# =========================
# 规则加载
# =========================

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _extract_domain_from_rule(line: str):
    s = line.strip()
    if not s or s.startswith("!") or s.startswith("#"):
        return None, False

    if "#" in s:
        s = s.split("#", 1)[0].strip()

    is_exception = False
    if s.startswith("@@"):
        is_exception = True
        s = s[2:].strip()

    if "$" in s:
        s = s.split("$", 1)[0].strip()

    parts = s.split()
    if len(parts) >= 2 and _IP_RE.match(parts[0]):
        s = parts[1]

    if s.startswith("||"):
        s = s[2:]
    elif s.startswith("|"):
        s = s[1:]

    if "://" in s:
        host = urlsplit(s).hostname
        s = host or s

    for sep in ("^", "/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]

    if ":" in s:
        s = s.split(":", 1)[0]

    s = s.lstrip(".")
    if s.startswith("*."):
        s = s[2:]

    d = _normalize_domain(s)
    if "." not in d:
        return None, False

    return d, is_exception


def _parse_rule_file(path: str):
    normal = set()
    exception = set()

    if not os.path.isfile(path):
        return frozenset(), frozenset()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            domain, is_exc = _extract_domain_from_rule(line)
            if not domain:
                continue
            if is_exc:
                exception.add(domain)
            else:
                normal.add(domain)

    return frozenset(normal), frozenset(exception)


def _load_local_rules():
    allow_normal, allow_exc = _parse_rule_file(ALLOWLIST_PATH)
    block_normal, block_exc = _parse_rule_file(BLOCKLIST_PATH)

    allowlist = set(allow_normal) | set(allow_exc)
    blocklist = set(block_normal)
    allow_exceptions = set(allowlist) | set(block_exc)

    return (
        frozenset(allowlist),
        frozenset(blocklist),
        frozenset(allow_exceptions),
    )


ALLOWLIST, BLOCKLIST, ALLOW_EXCEPTIONS = _load_local_rules()

# =========================
# DNS 处理
# =========================

def _decode_dns_param(dns_param: str) -> bytes:
    padding = "=" * (-len(dns_param) % 4)
    return base64.urlsafe_b64decode(dns_param + padding)


def _parse_dns_query_domain(query: bytes):
    i = 12
    labels = []

    while True:
        ln = query[i]
        i += 1
        if ln == 0:
            break
        labels.append(query[i:i + ln].decode("ascii", errors="ignore"))
        i += ln

    question_end = i + 4
    return _normalize_domain(".".join(labels)), question_end


def _build_nxdomain_response(query: bytes, question_end: int) -> bytes:
    txid = query[0:2]
    flags = b"\x81\x83"
    header = txid + flags + query[4:6] + b"\x00\x00\x00\x00\x00\x00"
    return header + query[12:question_end]


# =========================
# 缓存
# =========================

_RESP_CACHE = OrderedDict()
_CACHE_LOCK = threading.Lock()


def _cache_key(query: bytes) -> bytes:
    return query[2:]


def _cache_get(query: bytes):
    key = _cache_key(query)
    now = time.monotonic()

    with _CACHE_LOCK:
        item = _RESP_CACHE.get(key)
        if not item:
            return None
        expires, data = item
        if now >= expires:
            _RESP_CACHE.pop(key, None)
            return None
        _RESP_CACHE.move_to_end(key)
        return data


def _cache_set(query: bytes, body: bytes, ttl: int):
    key = _cache_key(query)
    expires = time.monotonic() + ttl

    with _CACHE_LOCK:
        _RESP_CACHE[key] = (expires, body)
        _RESP_CACHE.move_to_end(key)
        while len(_RESP_CACHE) > CACHE_MAX_ENTRIES:
            _RESP_CACHE.popitem(last=False)


# =========================
# 上游（顺序快速失败）
# =========================

def _forward_to_upstreams(dns_param: str):
    dns_param_quoted = quote(dns_param, safe="")

    for upstream in UPSTREAMS:
        try:
            url = f"{upstream}?dns={dns_param_quoted}"
            req = Request(
                url,
                headers={
                    "Accept": "application/dns-message",
                    "User-Agent": "doh-gateway",
                },
            )
            with urlopen(req, timeout=UPSTREAM_TIMEOUT) as resp:
                return resp.status, resp.read()
        except Exception:
            continue

    raise RuntimeError("All upstreams failed")


# =========================
# HTTP Handler
# =========================

class handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # 关闭日志，减少 CPU 消耗
        return

    def do_GET(self):
        parsed = urlsplit(self.path)

        if parsed.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"hello word")
            return

        if parsed.path != "/430624":
            self.send_response(404)
            self.end_headers()
            return

        params = parse_qs(parsed.query)
        dns_param = params.get("dns", [None])[0]
        if not dns_param:
            self.send_response(400)
            self.end_headers()
            return

        try:
            query = _decode_dns_param(dns_param)
            domain, question_end = _parse_dns_query_domain(query)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        is_exception_allow = _is_in_list_with_subdomain(domain, ALLOW_EXCEPTIONS)

        if (not is_exception_allow) and _is_in_list_with_subdomain(domain, BLOCKLIST):
            nxdomain = _build_nxdomain_response(query, question_end)
            self.send_response(200)
            self.send_header("Content-Type", "application/dns-message")
            self.end_headers()
            self.wfile.write(nxdomain)
            return

        if ALLOWLIST_ONLY and not is_exception_allow and not _is_in_list_with_subdomain(domain, ALLOWLIST):
            self.send_response(403)
            self.end_headers()
            return

        cached = _cache_get(query)
        if cached:
            body = query[0:2] + cached[2:]
            self.send_response(200)
            self.send_header("Content-Type", "application/dns-message")
            self.send_header("X-Cache", "HIT")
            self.end_headers()
            self.wfile.write(body)
            return

        try:
            status, body = _forward_to_upstreams(dns_param)

            if status == 200 and len(body) >= 12:
                ttl = DEFAULT_POSITIVE_TTL
                _cache_set(query, body, ttl)

            self.send_response(status)
            self.send_header("Content-Type", "application/dns-message")
            self.send_header("X-Cache", "MISS")
            self.end_headers()
            self.wfile.write(body)

        except Exception:
            self.send_response(502)
            self.end_headers()
