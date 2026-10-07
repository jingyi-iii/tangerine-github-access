#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tangerine.py - diagnose and optimize GitHub connectivity via the hosts file
               (Windows / Linux / macOS, standard library only)

Three layers, each runnable on its own:

  resolve   Multi-source cross-check. Queries the A records for the GitHub
            domains through two independent paths -- raw UDP packets sent
            straight to specific resolvers, and DoH over HTTPS -- so a
            poisoned local resolver cannot hide the truth. Prints a
            side-by-side table.

  probe     Live measurement per IP. Each candidate gets a TCP handshake
            timing plus a TLS handshake (full certificate verification first;
            if that fails, retry without verification to tell "handshake
            killed by RST" apart from "handshake fine, wrong certificate").
            Wrong-certificate IPs are rejected -- this filters out the fake
            addresses that accept TCP but are really black holes or middleboxes.

  optimize  Probe, then pick a winner per domain and write it into a managed
            block in hosts. The file is backed up first, and restore undoes it.

Usage:
    python tangerine.py resolve                # just compare DNS sources
    python tangerine.py probe                  # full probe, changes nothing
    python tangerine.py optimize               # probe and write hosts
    python tangerine.py optimize --dry-run     # see what would be written
    python tangerine.py restore                # remove the managed block
    python tangerine.py show                   # print the managed block

Platform notes:
    Windows  writes %SystemRoot%\\System32\\drivers\\etc\\hosts and needs
             administrator rights. Double-clicking optimize-as-admin.bat
             triggers the UAC prompt for you.
    Linux    writes /etc/hosts and needs sudo. Two extra checks are run
             because they decide whether writing hosts helps at all:
               - is "files" listed before "dns" in /etc/nsswitch.conf?
               - is IPv6 enabled locally but unable to reach GitHub?
    macOS    writes /etc/hosts, needs sudo, flushes via dscacheutil plus
             mDNSResponder.

Remember: literal IPs in hosts go stale. Re-run optimize every couple of
weeks, or put it on a schedule (Task Scheduler / cron).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

APP = "tangerine"
VERSION = "1.0.0"
SYSTEM = platform.system()
IS_WIN = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"
IS_LINUX = SYSTEM == "Linux"
NEWLINE = "\r\n" if IS_WIN else "\n"

if IS_WIN:
    HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows"),
                      "System32", "drivers", "etc", "hosts")
    PRIV_HINT = "administrator"
else:
    HOSTS_PATH = Path("/etc/hosts")
    PRIV_HINT = "root"

MARK_BEGIN = "# >>> tangerine managed block begin"
MARK_END = "# <<< tangerine managed block end"

# Every domain GitHub actually uses. Miss one and that feature stays slow.
TARGETS = [
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "avatars.githubusercontent.com",
    "github.global.ssl.fastly.net",
]

# Plain UDP resolvers, queried directly. The first five are reachable from
# mainland China; the last two are usually blocked or hijacked there and are
# kept as reference -- their failure is itself part of the evidence.
DNS_SERVERS = [
    "223.5.5.5",        # AliDNS
    "223.6.6.6",        # AliDNS
    "119.29.29.29",     # DNSPod
    "180.76.76.76",     # Baidu
    "114.114.114.114",  # 114DNS
    "8.8.8.8",          # Google (reference)
    "1.1.1.1",          # Cloudflare (reference)
]

# DoH: rides HTTPS, so UDP/53 tampering does not apply.
DOH_ENDPOINTS = [
    ("alidns", "https://dns.alidns.com/resolve?name={name}&type=A"),
    ("dnspod", "https://doh.pub/dns-query?name={name}&type=A&ct=application%2Fdns-json"),
    ("cf", "https://cloudflare-dns.com/dns-query?name={name}&type=A"),
]

PORT = 443

# After this many consecutive failures a DNS source is dropped for the rest
# of the run, otherwise every domain pays its timeout again.
DEAD_AFTER = 2
_SOURCE_FAILURES: dict[str, int] = {}


def _source_dead(name: str) -> bool:
    return _SOURCE_FAILURES.get(name, 0) >= DEAD_AFTER

# --------------------------------------------------------------------------
# Terminal output
# --------------------------------------------------------------------------

_USE_COLOR = False


def _enable_vt() -> None:
    """Legacy cmd.exe needs ANSI escape support switched on explicitly."""
    if not IS_WIN:
        return
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def setup_terminal() -> None:
    global _USE_COLOR
    _enable_vt()
    try:
        _USE_COLOR = sys.stdout.isatty()
    except Exception:
        _USE_COLOR = False


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def green(t: str) -> str:
    return _c("32", t)


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


def cyan(t: str) -> str:
    return _c("36", t)


def dim(t: str) -> str:
    return _c("2", t)


def bold(t: str) -> str:
    return _c("1", t)


def out(msg: str = "") -> None:
    print(msg)


def hr(n: int = 78) -> None:
    out(dim("-" * n))


# --------------------------------------------------------------------------
# DNS: build the wire format ourselves and talk to a specific server,
# bypassing the system resolver entirely
# --------------------------------------------------------------------------

QTYPE_A = 1


def _build_query(host: str, qtype: int = QTYPE_A) -> tuple[int, bytes]:
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b""
    for label in host.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode("ascii")
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    return tid, header + qname + struct.pack(">HH", qtype, 1)


def _skip_name(buf: bytes, off: int) -> int:
    """Skip a domain name (compression pointers included), return the offset after it."""
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        length = buf[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def _parse_answers(buf: bytes, qtype: int = QTYPE_A) -> list[str]:
    if len(buf) < 12:
        raise ValueError("short dns header")
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"rcode={rcode}")
    off = 12
    for _ in range(qd):
        off = _skip_name(buf, off) + 4
    found: list[str] = []
    for _ in range(an):
        off = _skip_name(buf, off)
        if off + 10 > len(buf):
            break
        atype, aclass, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        off += rdlen
        if aclass == 1 and atype == qtype == QTYPE_A and rdlen == 4:
            found.append(socket.inet_ntoa(rdata))
        elif aclass == 1 and atype == 5:  # CNAME; the answer section usually carries the A too
            continue
    return found


def dns_udp(server: str, host: str, timeout: float = 3.0) -> list[str]:
    tid, packet = _build_query(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    r_tid = struct.unpack(">H", data[:2])[0]
    if r_tid != tid:
        raise ValueError("transaction id mismatch (an on-path device likely forged the reply)")
    flags = struct.unpack(">H", data[2:4])[0]
    if flags & 0x0200:  # TC: truncated, retry over TCP
        return dns_tcp(server, host, timeout)
    return _parse_answers(data)


def dns_tcp(server: str, host: str, timeout: float = 4.0) -> list[str]:
    _, packet = _build_query(host)
    with socket.create_connection((server, 53), timeout=timeout) as sock:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        head = sock.recv(2)
        if len(head) < 2:
            raise ValueError("short tcp answer")
        need = struct.unpack(">H", head)[0]
        chunks, got = [], 0
        while got < need:
            chunk = sock.recv(need - got)
            if not chunk:
                break
            chunks.append(chunk)
            got += len(chunk)
    return _parse_answers(b"".join(chunks))


def dns_doh(name: str, url: str, host: str, timeout: float = 5.0) -> list[str]:
    req = urllib.request.Request(
        url.format(name=host),
        headers={"accept": "application/dns-json", "user-agent": f"{APP}/{VERSION}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))
    ips = []
    for ans in payload.get("Answer", []) or []:
        if ans.get("type") == QTYPE_A and ans.get("data"):
            ips.append(ans["data"])
    if not ips and payload.get("Status") not in (0, None):
        raise ValueError(f"doh status={payload.get('Status')}")
    return ips


def is_usable_ip(ip: str) -> bool:
    """Reject 127.0.0.1 / 0.0.0.0 / private / reserved addresses -- the shapes
    that poisoned answers come in."""
    try:
        addr = socket.inet_aton(ip)
    except OSError:
        return False
    octets = list(addr)
    a, b = octets[0], octets[1]
    if a == 0 or a == 127 or a >= 224:
        return False
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:  # CGNAT
        return False
    return True


def gather_candidates(host: str, timeout: float, workers: int) -> dict[str, dict]:
    """Ask every DNS source for candidate IPs.

    Both the raw answer and the filtered answer are kept. "The raw answer
    contained 127.0.0.1" is direct evidence of poisoning and must not be
    quietly discarded.

    Blocked sources (8.8.8.8 / 1.1.1.1 / Cloudflare DoH are unreachable from
    mainland China) stop being queried after a couple of failures, otherwise
    every domain pays their timeout again.
    """
    jobs = []
    for server in DNS_SERVERS:
        name = f"udp://{server}"
        if _source_dead(name):
            continue
        jobs.append((name, lambda s=server: dns_udp(s, host, timeout)))
    for label, url in DOH_ENDPOINTS:
        name = f"doh://{label}"
        if _source_dead(name):
            continue
        jobs.append((name, lambda u=url, lb=label: dns_doh(lb, u, host, timeout)))

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(jobs)))) as pool:
        futures = {pool.submit(fn): name for name, fn in jobs}
        for fut in futures:
            name = futures[fut]
            try:
                raw = list(dict.fromkeys(fut.result()))
                polluted = [ip for ip in raw if not is_usable_ip(ip)]
                clean = [ip for ip in raw if is_usable_ip(ip)]
                results[name] = {
                    "raw": raw,
                    "ips": clean,
                    "polluted": polluted,
                    "error": "" if raw else "no A record",
                }
                _SOURCE_FAILURES[name] = 0
            except Exception as exc:
                results[name] = {
                    "raw": [], "ips": [], "polluted": [],
                    "error": f"{type(exc).__name__}: {exc}",
                }
                if isinstance(exc, (TimeoutError, socket.timeout, urllib.error.URLError)):
                    _SOURCE_FAILURES[name] = _SOURCE_FAILURES.get(name, 0) + 1
                else:
                    _SOURCE_FAILURES[name] = 0
    return results


def dead_sources() -> list[str]:
    return sorted(n for n, c in _SOURCE_FAILURES.items() if c >= DEAD_AFTER)


# --------------------------------------------------------------------------
# Probing: TCP + TLS
# --------------------------------------------------------------------------

@dataclass
class Probe:
    host: str
    ip: str
    tcp_ms: float | None = None
    tls_ms: float | None = None
    attempts: int = 0          # rounds actually run
    verified_rounds: int = 0   # rounds where full certificate verification passed
    handshake_rounds: int = 0  # rounds where TLS completed at any verification level
    consensus: int = 0         # how many DNS sources independently returned this IP
    error: str = ""

    @property
    def verified(self) -> bool:
        return self.verified_rounds > 0

    @property
    def handshake_ok(self) -> bool:
        return self.handshake_rounds > 0

    @property
    def stability(self) -> float:
        return self.verified_rounds / self.attempts if self.attempts else 0.0

    @property
    def latency(self) -> float:
        return (self.tcp_ms or 0.0) + (self.tls_ms or 0.0)

    @property
    def usable(self) -> bool:
        return self.verified

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update({
            "verified": self.verified,
            "handshake_ok": self.handshake_ok,
            "usable": self.usable,
            "stability": round(self.stability, 2),
            "latency_ms": round(self.latency, 1),
        })
        return d


def _tls_handshake(ip: str, host: str, timeout: float, verify: bool) -> tuple[float, str]:
    """Returns (elapsed_ms, error). verify=True checks the full chain and hostname."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, PORT))
        t0 = time.perf_counter()
        with ctx.wrap_socket(sock, server_hostname=host):
            elapsed = (time.perf_counter() - t0) * 1000.0
        return elapsed, ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_one(host: str, ip: str, timeout: float, rounds: int = 3) -> Probe:
    """Sample several rounds. The single fastest round is not trustworthy --
    on a mainland-China uplink the same IP can answer in 100 ms one moment and
    time out the next, so we also count how many rounds succeeded and sort by
    stability first."""
    result = Probe(host=host, ip=ip, attempts=max(1, rounds))
    best_tcp: float | None = None
    best_tls: float | None = None
    last_err = ""
    dead_rounds = 0
    executed = 0

    for _ in range(max(1, rounds)):
        executed += 1
        t0 = time.perf_counter()
        try:
            conn = socket.create_connection((ip, PORT), timeout=timeout)
            tcp_ms = (time.perf_counter() - t0) * 1000.0
            conn.close()
        except OSError as exc:
            last_err = f"tcp: {type(exc).__name__}"
            dead_rounds += 1
            if dead_rounds >= 2:
                break  # two rounds without even a TCP handshake: stop wasting time
            continue
        if best_tcp is None or tcp_ms < best_tcp:
            best_tcp = tcp_ms

        try:
            tls_ms, _ = _tls_handshake(ip, host, timeout, verify=True)
            result.verified_rounds += 1
            result.handshake_rounds += 1
            dead_rounds = 0
            if best_tls is None or tls_ms < best_tls:
                best_tls = tls_ms
            continue
        except ssl.SSLCertVerificationError as exc:
            last_err = f"cert verify failed: {getattr(exc, 'verify_message', None) or exc}"
        except Exception as exc:  # noqa: BLE001
            last_err = f"tls: {type(exc).__name__}"

        # Full verification failed. Fall back to handshaking without it, which
        # separates "killed by RST / black hole" from "handshake fine, but the
        # certificate belongs to someone else".
        try:
            tls_ms, _ = _tls_handshake(ip, host, timeout, verify=False)
            result.handshake_rounds += 1
            dead_rounds = 0
            if best_tls is None or tls_ms < best_tls:
                best_tls = tls_ms
        except Exception:
            dead_rounds += 1
            if dead_rounds >= 2:
                break

    result.attempts = executed
    result.tcp_ms = best_tcp
    result.tls_ms = best_tls
    result.error = "" if result.handshake_ok else last_err
    return result


def probe_host(host: str, ips: list[str], timeout: float, rounds: int, workers: int,
               consensus: dict[str, int] | None = None) -> list[Probe]:
    consensus = consensus or {}
    results: list[Probe] = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ips)))) as pool:
        futures = [pool.submit(probe_one, host, ip, timeout, rounds) for ip in ips]
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                results.append(Probe(host=host, ip="?", error=f"{type(exc).__name__}: {exc}"))
    for p in results:
        p.consensus = consensus.get(p.ip, 0)
    results.sort(key=lambda p: (not p.verified, -p.stability, -p.consensus, p.latency))
    return results


def pick_best(probes: list[Probe]) -> Probe | None:
    """Stability, then cross-source consensus, then latency.

    A steady 150 ms IP that most resolvers agree on beats a flapping address
    that only one source hands out.
    """
    usable = [p for p in probes if p.usable]
    if not usable:
        return None
    usable.sort(key=lambda p: (-p.stability, -p.consensus, p.latency))
    return usable[0]


# --------------------------------------------------------------------------
# hosts file handling
# --------------------------------------------------------------------------

def decode_hosts(raw: bytes) -> str:
    """surrogateescape keeps undecodable bytes intact on the way back out,
    so entries the user already has are never mangled."""
    return raw.decode("utf-8", errors="surrogateescape")


def read_hosts(path: Path = HOSTS_PATH) -> str:
    if not path.exists():
        return ""
    return decode_hosts(path.read_bytes())


def strip_block(text: str) -> str:
    lines = text.replace("\r\n", "\n").split("\n")
    kept, skipping = [], False
    for line in lines:
        if line.strip() == MARK_BEGIN:
            skipping = True
            continue
        if line.strip() == MARK_END:
            skipping = False
            continue
        if not skipping:
            kept.append(line)
    return "\n".join(kept).strip("\n")


def render_block(entries: list[tuple[str, str, float]]) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        MARK_BEGIN,
        f"# generated by {APP} {VERSION} at {stamp}",
        f"# these IPs drift; re-run every couple of weeks: python {Path(__file__).name} optimize",
        f"# to undo: python {Path(__file__).name} restore",
        "",
    ]
    for host, ip, ms in entries:
        lines.append(f"{ip:<16}{host}")
    lines.append("")
    for host, ip, ms in entries:
        lines.append(f"# {host} -> {ip}  ({ms:.0f} ms)")
    lines.append(MARK_END)
    return "\n".join(lines)


def write_hosts(text: str, path: Path = HOSTS_PATH) -> Path:
    backup = path.with_name(f"{path.name}.{APP}-backup-{datetime.now():%Y%m%d-%H%M%S}.bak")
    shutil.copy2(path, backup)
    payload = text.replace("\r\n", "\n")
    if NEWLINE != "\n":
        payload = payload.replace("\n", NEWLINE)
    if not payload.endswith(NEWLINE):
        payload += NEWLINE
    path.write_bytes(payload.encode("utf-8", errors="surrogateescape"))
    return backup


def is_admin() -> bool:
    if not IS_WIN:
        return os.geteuid() == 0
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _flush_candidates() -> list[list[str]]:
    """Cache flushing differs per distro; try them in order of availability."""
    if IS_WIN:
        return [["ipconfig", "/flushdns"]]
    if IS_MAC:
        return [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]]
    return [
        ["resolvectl", "flush-caches"],         # systemd-resolved (newer)
        ["systemd-resolve", "--flush-caches"],  # systemd-resolved (older)
        ["nscd", "-i", "hosts"],                # nscd
        ["service", "nscd", "restart"],
    ]


def flush_dns() -> str:
    tried: list[str] = []
    for cmd in _flush_candidates():
        if shutil.which(cmd[0]) is None:
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except Exception as exc:  # noqa: BLE001
            tried.append(f"{cmd[0]}({type(exc).__name__})")
            continue
        if proc.returncode == 0:
            return "ran " + " ".join(cmd)
        tried.append(f"{cmd[0]}(exit {proc.returncode})")
    if tried:
        return "no flush command succeeded: " + ", ".join(tried)
    return "nothing to flush (no DNS cache service detected)"


# --------------------------------------------------------------------------
# Platform checks: will writing hosts actually do anything?
# --------------------------------------------------------------------------

def check_nsswitch(text: str) -> str:
    """Pure function so it can be tested on its own: check the lookup order of
    the hosts entry in nsswitch.conf."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or not line.startswith("hosts:"):
            continue
        parts = line.split(":", 1)[1].split()
        if "files" not in parts:
            return f'the hosts line in /etc/nsswitch.conf has no "files" -- writing hosts will do nothing: {line}'
        if "dns" in parts and parts.index("dns") < parts.index("files"):
            return f'"dns" comes before "files" in /etc/nsswitch.conf -- hosts will be skipped: {line}'
        return ""
    return ""


def hosts_priority_warning() -> str:
    """Linux-specific. If the hosts line in nsswitch.conf does not put files
    ahead of dns, nothing written to /etc/hosts is ever consulted."""
    conf = Path("/etc/nsswitch.conf")
    if IS_WIN or not conf.exists():
        return ""
    try:
        return check_nsswitch(conf.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""


def _has_global_ipv6() -> bool:
    """Does this machine actually hold a global IPv6 address (link-local doesn't count)?"""
    proc = Path("/proc/net/if_inet6")
    if not proc.exists():
        return False
    try:
        for line in proc.read_text(errors="replace").splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[3] == "00":  # scope 00 = global
                return True
    except OSError:
        pass
    return False


def ipv6_note(host: str = "github.com", timeout: float = 2.0) -> str:
    """A subtle Linux trap: the machine has IPv6, RFC 3484 makes the stack
    prefer it, but GitHub's IPv6 is unreachable -- so the perfect IPv4 entry
    in hosts does nothing and every request stalls on IPv6 first."""
    if IS_WIN or not socket.has_ipv6 or not _has_global_ipv6():
        return ""
    try:
        infos = socket.getaddrinfo(host, PORT, socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return ""
    if not infos:
        return ""
    addr = infos[0][4]
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(addr)
            return ""
        finally:
            sock.close()
    except OSError as exc:
        return (f"{host} resolves to IPv6 {addr[0]} but the connection fails "
                f"({type(exc).__name__}), and this machine has IPv6 enabled, so the "
                f"stack may prefer it and still stall.\n"
                f"Append this line to /etc/gai.conf to prefer IPv4:\n"
                f"    precedence ::ffff:0:0/96  100")


def in_container() -> bool:
    if not IS_LINUX:
        return False
    if Path("/.dockerenv").exists():
        return True
    try:
        cgroup = Path("/proc/1/cgroup").read_text(errors="replace")
    except OSError:
        return False
    return any(k in cgroup for k in ("docker", "kubepods", "containerd", "lxc"))


def platform_notes() -> list[str]:
    notes: list[str] = []
    warn = hosts_priority_warning()
    if warn:
        notes.append(warn)
    if in_container():
        notes.append("container detected: changes to /etc/hosts are lost when the "
                     "container is rebuilt and may be overwritten by the orchestrator")
    note = ipv6_note()
    if note:
        notes.append(note)
    return notes


def print_platform_notes() -> None:
    for note in platform_notes():
        lines = note.split("\n")
        out(yellow("NOTE  ") + lines[0])
        for extra in lines[1:]:
            out("      " + extra)


# --------------------------------------------------------------------------
# The three stages
# --------------------------------------------------------------------------

def cmd_resolve(args) -> int:
    domains = args.domains or TARGETS
    out(bold(f"{APP} resolve - multi-source DNS cross-check"))
    out(dim("Compares the A records every source returns. 127.0.0.1 / 0.0.0.0 / "
            "private ranges mean that source is poisoned."))
    hr()
    payload: dict[str, dict] = {}

    for host in domains:
        out("")
        out(bold(host))
        info = gather_candidates(host, args.timeout, args.workers)
        payload[host] = info
        polluted_hits = 0
        clean_pool: set[str] = set()

        for source, data in sorted(info.items()):
            if data["error"]:
                out(f"  {source:<22} {red('no answer ')} {dim(data['error'])}")
                continue
            label = "ok" if data["raw"] else "empty"
            status = (green if data["raw"] else yellow)(f"{label:<10}")
            shown = []
            for ip in data["raw"]:
                if is_usable_ip(ip):
                    shown.append(ip)
                    clean_pool.add(ip)
                else:
                    shown.append(red(f"{ip}[polluted]"))
                    polluted_hits += 1
            out(f"  {source:<22} {status} {', '.join(shown) or '-'}")

        ok_sources = sum(1 for d in info.values() if d["ips"])
        counter: dict[str, int] = {}
        for d in info.values():
            for ip in set(d["ips"]):
                counter[ip] = counter.get(ip, 0) + 1

        if polluted_hits:
            out(f"  {yellow('verdict')}   {polluted_hits} source(s) returned unusable "
                f"addresses -- this domain's resolution is poisoned")
        elif not clean_pool:
            out(f"  {red('verdict')}   no source returned a usable address")
        else:
            top_ip, top_n = max(counter.items(), key=lambda kv: kv[1])
            if ok_sources >= 3 and top_n / ok_sources < 0.5:
                out(f"  {red('diverged')}  best consensus {top_ip} comes from only "
                    f"{top_n}/{ok_sources} sources and the rest disagree -- "
                    f"signature of poisoning or wildcard DNS")
            elif len(clean_pool) == 1:
                out(f"  {green('consensus')} all {ok_sources} sources agree: {top_ip}")
            else:
                out(f"  {dim('consensus')} {top_ip} backed by {top_n}/{ok_sources} sources, "
                    f"{len(clean_pool)} address(es) total")

    skipped = dead_sources()
    if skipped:
        out("")
        out(dim(f"dropped unreachable sources (repeated timeouts): {', '.join(skipped)}"))

    if args.json:
        out("")
        out(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_probe(args) -> int:
    return _run_probe(args, apply_changes=False)


def cmd_optimize(args) -> int:
    return _run_probe(args, apply_changes=not args.dry_run)


@dataclass
class DomainOutcome:
    host: str
    lines: list[str] = field(default_factory=list)
    entry: tuple[str, str, float] | None = None
    report: dict = field(default_factory=dict)


def _process_domain(host: str, args, extra: dict[str, list[str]]) -> DomainOutcome:
    """Resolve -> tally consensus -> probe each IP -> pick the winner.

    Written as a pure function (it never prints) so several domains can run in
    parallel and their output can be printed in the original order afterwards.
    Interleaved output would be unreadable.
    """
    lines: list[str] = []
    sources = gather_candidates(host, args.timeout, args.workers)

    # How many sources independently returned each candidate IP. An address
    # only one source knows about deserves suspicion.
    consensus: dict[str, int] = {}
    for data in sources.values():
        for ip in set(data["ips"]):
            consensus[ip] = consensus.get(ip, 0) + 1

    candidates: list[str] = list(extra.get(host, []))
    for data in sources.values():
        for ip in data["ips"]:
            if ip not in candidates:
                candidates.append(ip)

    polluted = sorted({ip for d in sources.values() for ip in d.get("polluted", [])})
    if polluted:
        lines.append(dim(f"  unusable addresses found in DNS answers, dropped: {', '.join(polluted)}"))

    ok_sources = sum(1 for d in sources.values() if d["ips"])
    if ok_sources >= 3 and consensus:
        top_ip, top_n = max(consensus.items(), key=lambda kv: kv[1])
        if top_n / ok_sources < 0.5:
            lines.append(yellow(
                f"  sources disagree wildly (best consensus only {top_n}/{ok_sources}), "
                f"possible hijack or wildcard DNS"))

    if not candidates:
        lines.append(f"  {red('no candidate IP')}  no DNS source returned a usable A record")
        return DomainOutcome(host, lines, None, {
            "candidates": [], "sources": sources, "chosen": None, "probes": [],
        })

    probes = probe_host(host, candidates, args.timeout, args.rounds, args.workers, consensus)
    for p in probes:
        tcp = f"{p.tcp_ms:7.1f}ms" if p.tcp_ms is not None else "        -"
        tls = f"{p.tls_ms:7.1f}ms" if p.tls_ms is not None else "        -"
        row = (f"  {p.ip:<16} tcp {tcp}  tls {tls}  "
               f"ok {p.verified_rounds}/{p.attempts}  src {p.consensus}/{ok_sources or 1}  ")
        # Colour last so the padding never ends up inside the escape sequence.
        if p.verified:
            row += green("verified")
        elif p.handshake_ok:
            row += yellow("cert mismatch")
        else:
            row += red("unreachable")
        if p.error:
            row += dim(f"  {p.error}")
        lines.append(row.rstrip())

    chosen = pick_best(probes)
    entry = None
    if chosen:
        lines.append(f"  {cyan('picked')}   {chosen.ip}  "
                     f"(tcp {chosen.tcp_ms:.0f} + tls {chosen.tls_ms:.0f} = {chosen.latency:.0f} ms, "
                     f"ok {chosen.verified_rounds}/{chosen.attempts}, "
                     f"{chosen.consensus} sources agree)")
        entry = (host, chosen.ip, chosen.latency)
    else:
        lines.append(f"  {yellow('skipped')}  no IP passed certificate verification, "
                     f"so this domain is not written to hosts")

    return DomainOutcome(host, lines, entry, {
        "sources": sources,
        "candidates": candidates,
        "probes": [p.to_dict() for p in probes],
        "chosen": chosen.ip if chosen else None,
    })


def _admin_hint() -> None:
    if IS_WIN:
        out(red(f"Writing {HOSTS_PATH} requires administrator rights."))
        out(dim("Re-run with elevation:"))
        out(dim('  -> press Win, type "cmd", right-click it and pick "Run as administrator", then:'))
        out(dim(f"  -> python {Path(__file__).name} optimize"))
        out(dim("  -> or just double-click optimize-as-admin.bat (it raises the UAC prompt)"))
    else:
        out(red(f"Writing {HOSTS_PATH} requires root."))
        out(dim("Re-run with privileges:"))
        out(dim(f"  -> sudo python3 {Path(__file__).name} optimize"))
    out(dim("Adding --dry-run shows the result without writing anything."))


def _run_probe(args, apply_changes: bool) -> int:
    if apply_changes and not is_admin():
        _admin_hint()
        return 2

    domains = args.domains or TARGETS
    parallel = max(1, min(args.domain_parallel, len(domains)))
    out(bold(f"{APP} {'optimize' if apply_changes else 'probe'} - per-IP live measurement"))
    out(dim(f"{len(domains)} domains | timeout {args.timeout}s | {args.rounds} rounds/IP | "
            f"{args.workers} IP workers | {parallel} domain workers"))
    hr()
    print_platform_notes()

    report: dict[str, dict] = {}
    entries: list[tuple[str, str, float]] = []
    extra = _parse_extra_ips(args.extra_ip)

    if parallel > 1:
        # Domains are independent, so running them in parallel stacks up the
        # dead-IP timeouts instead of paying them one after another.
        with ThreadPoolExecutor(max_workers=parallel) as pool:
            outcomes = list(pool.map(lambda h: _process_domain(h, args, extra), domains))
    else:
        outcomes = [_process_domain(h, args, extra) for h in domains]

    for oc in outcomes:
        out("")
        out(bold(oc.host))
        for line in oc.lines:
            out(line)
        if oc.entry:
            entries.append(oc.entry)
        report[oc.host] = oc.report

    skipped = dead_sources()
    if skipped:
        out("")
        out(dim(f"dropped unreachable sources (repeated timeouts): {', '.join(skipped)}"))

    if not entries:
        out("")
        hr()
        out(red("No domain produced a usable IP."))
        out(dim("Usual causes: the machine is fully offline, or both UDP/53 and DoH are blocked."))
        out(dim("You can supply candidates by hand: --extra-ip github.com=140.82.112.3"))
        return 1

    block = render_block(entries)
    out("")
    hr()
    out(bold("Proposed hosts block"))
    out("")
    for line in block.splitlines():
        out("  " + (dim(line) if line.startswith("#") else cyan(line)))

    if args.json:
        out("")
        out(json.dumps(report, ensure_ascii=False, indent=2, default=str))

    if not apply_changes:
        out("")
        out(dim(f"probe mode changes nothing. Run optimize (needs {PRIV_HINT}) to write the block above."))
        return 0

    current = read_hosts()
    merged = strip_block(current)
    new_text = (merged + "\n\n" if merged else "") + block + "\n"
    if new_text.strip() == current.strip():
        out("")
        out(green("hosts is already up to date; nothing to change."))
        return 0

    backup = write_hosts(new_text)
    out("")
    out(green(f"wrote {HOSTS_PATH}"))
    out(dim(f"backup: {backup}"))
    out(dim(f"DNS cache: {flush_dns()}"))

    out("")
    out(bold("Post-write recheck"))
    for host, ip, _ in entries:
        p = probe_one(host, ip, args.timeout, rounds=1)
        status = green("ok") if p.verified else red("failed")
        out(f"  {host:<40} {ip:<16} {status}")
    return 0


def _parse_extra_ips(items: list[str] | None) -> dict[str, list[str]]:
    extra: dict[str, list[str]] = {}
    for item in items or []:
        if "=" not in item:
            continue
        host, ip = item.split("=", 1)
        extra.setdefault(host.strip(), []).append(ip.strip())
    return extra


def cmd_restore(args) -> int:
    if not is_admin() and args.write:
        _admin_hint()
        return 2
    current = read_hosts()
    if MARK_BEGIN not in current:
        out(yellow("no tangerine managed block in hosts; nothing to restore."))
        return 0
    merged = strip_block(current)
    new_text = (merged + "\n") if merged else "\n"
    if not args.write:
        out(bold("Managed block that would be removed:"))
        inside = False
        for line in current.replace("\r\n", "\n").split("\n"):
            if line.strip() == MARK_BEGIN:
                inside = True
            if inside:
                out("  " + red(line))
            if line.strip() == MARK_END:
                inside = False
        out("")
        out(dim("Preview only. Add --write to actually do it."))
        return 0
    backup = write_hosts(new_text)
    out(green("managed block removed."))
    out(dim(f"backup: {backup}"))
    out(dim(f"DNS cache: {flush_dns()}"))
    return 0


def cmd_show(args) -> int:
    current = read_hosts()
    if MARK_BEGIN not in current:
        out(yellow("hosts has no tangerine managed block."))
        return 0
    inside = False
    for line in current.replace("\r\n", "\n").split("\n"):
        if line.strip() == MARK_BEGIN:
            inside = True
        if inside:
            out(line)
        if line.strip() == MARK_END:
            inside = False
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

COMMANDS = ("resolve", "probe", "optimize", "restore", "show")
# Flags that belong to the top-level parser and must not be pushed behind a
# subcommand.
MAIN_FLAGS = ("-h", "--help", "--version")


def build_parser() -> argparse.ArgumentParser:
    # Shared options live on each subcommand -- argparse subparsers do not
    # inherit the parent's options, and `tangerine.py probe --timeout 5` is
    # what people naturally type.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--timeout", type=float, default=2.5,
                        help="per-handshake timeout in seconds (default 2.5; anything "
                             "slower than that is unusable across a border anyway)")
    common.add_argument("--rounds", type=int, default=3,
                        help="samples per IP, used to measure stability (default 3)")
    common.add_argument("--workers", type=int, default=12,
                        help="IP-level concurrency (default 12)")
    common.add_argument("--domain-parallel", type=int, default=3,
                        help="domain-level concurrency, 1 for serial (default 3)")
    common.add_argument("--json", action="store_true", help="also print a JSON report")
    common.add_argument("--version", action="version", version=f"{APP} {VERSION}",
                        help="show the version and exit")
    common.add_argument("--domains", nargs="+", metavar="HOST",
                        help="only handle these domains (default: the full GitHub set)")
    common.add_argument("--extra-ip", action="append", metavar="HOST=IP",
                        help="add a candidate IP by hand, repeatable. Useful when DNS is "
                             "fully poisoned and no candidate can be discovered")

    parser = argparse.ArgumentParser(
        prog=APP,
        description="Diagnose and optimize GitHub connectivity through the hosts file "
                    "(layered: DNS cross-check + live TCP/TLS probing)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python tangerine.py resolve                 compare DNS sources
  python tangerine.py probe                   full probe, writes nothing
  python tangerine.py optimize --dry-run      show what would be written
  python tangerine.py optimize                write the hosts block (needs privileges)
  python tangerine.py restore --write         undo it
  python tangerine.py probe --extra-ip github.com=140.82.112.3
""",
    )
    parser.add_argument("--version", action="version", version=f"{APP} {VERSION}")

    subs = parser.add_subparsers(dest="cmd")
    subs.required = False

    p = subs.add_parser("resolve", parents=[common], help="cross-check DNS sources (read-only)")
    p.set_defaults(func=cmd_resolve)

    p = subs.add_parser("probe", parents=[common], help="probe every candidate IP over TCP/TLS (read-only)")
    p.set_defaults(func=cmd_probe)

    p = subs.add_parser("optimize", parents=[common], help="probe and write the hosts block")
    p.add_argument("--dry-run", action="store_true", help="show the result without writing")
    p.set_defaults(func=cmd_optimize)

    p = subs.add_parser("restore", parents=[common], help="remove the tangerine managed block")
    p.add_argument("--write", action="store_true", help="actually do it (default is preview only)")
    p.set_defaults(func=cmd_restore)

    p = subs.add_parser("show", parents=[common], help="print the current managed block")
    p.set_defaults(func=cmd_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    setup_terminal()
    parser = build_parser()
    rest = list(sys.argv[1:] if argv is None else argv)

    # Without a subcommand, default to probe. Shared options only exist on the
    # subparsers, so if none of them appears, prepend "probe" -- that makes
    # `tangerine.py --json` and `tangerine.py probe --json` equivalent.
    # Top-level flags such as --version must be left for the main parser.
    if not any(tok in COMMANDS for tok in rest) and not any(tok in MAIN_FLAGS for tok in rest):
        rest = ["probe", *rest]

    args = parser.parse_args(rest)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        out("")
        out(yellow("interrupted."))
        return 130
    except Exception as exc:  # noqa: BLE001
        out(red(f"error: {type(exc).__name__}: {exc}"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
