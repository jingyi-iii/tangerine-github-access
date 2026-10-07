# tangerine — GitHub access diagnostics and hosts optimization

[![CI](https://github.com/jingyi-iii/tangerine-github-access/actions/workflows/ci.yml/badge.svg)](https://github.com/jingyi-iii/tangerine-github-access/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Platforms](https://img.shields.io/badge/platforms-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)](#what-changes-between-platforms)

A single-file tool for **Windows / Linux / macOS**. **Standard library only** —
nothing to install, no `pip install`, no virtualenv.

The core idea: "GitHub is slow" is not one problem, it is four. The tool takes
them apart layer by layer, so each one can be verified on its own — and any
change can be rolled back.

```
DNS poisoning  ->  SNI / RST  ->  cross-border congestion  ->  CDN & git protocol
   resolve          probe               probe                      probe
```

Most "optimize GitHub" scripts jump straight to writing the fastest IP they can
find into the hosts file. That approach has two failure modes this tool is built
to avoid:

- **The fastest IP is often a decoy.** An address that accepts TCP but presents
  the wrong TLS certificate is a middlebox. Sorting by TCP latency picks it
  every time.
- **The bottleneck is frequently not DNS at all.** If cross-border packet loss
  is the problem, hosts cannot help — and you should know that before spending
  an evening on it.

---

## Requirements

- Python **3.9 or newer**. No third-party packages.
- Administrator / `root` to write the hosts file. Everything else runs
  unprivileged.

---

## Quick start

```bash
python tangerine.py resolve      # is the DNS poisoned? read-only, touches nothing
python tangerine.py probe        # full measurement, still read-only
python tangerine.py optimize     # measure and write hosts (needs privileges)
```

Writing hosts needs privileges, so there is a launcher per platform that handles
the elevation for you:

| Platform | hosts path | Elevate with |
|---|---|---|
| Windows | `%SystemRoot%\System32\drivers\etc\hosts` | `optimize-as-admin.bat` (double-click, or run it) |
| Linux | `/etc/hosts` | `./optimize-as-root.sh` |
| macOS | `/etc/hosts` | `./optimize-as-root.sh` |

Or do it by hand if you prefer:

```bash
# Windows: open a terminal as administrator, then
python tangerine.py optimize

# Linux / macOS
sudo python3 tangerine.py optimize
```

Not happy with the result?

```bash
python tangerine.py restore              # preview what would be removed
python tangerine.py restore --write      # actually remove it
```

---

## The launchers

Both do the same three things: find a Python interpreter, work out which
subcommand you asked for, and re-run themselves with privileges. They accept
every tangerine flag, and they take a subcommand as the first argument
(defaulting to `optimize`):

```bash
./optimize-as-root.sh                                     # optimize
./optimize-as-root.sh --dry-run                           # measure only
./optimize-as-root.sh --domains github.com --rounds 5     # pass flags through
./optimize-as-root.sh restore --write                     # undo
```

```bat
optimize-as-admin.bat
optimize-as-admin.bat --dry-run
optimize-as-admin.bat --domains github.com --rounds 5
optimize-as-admin.bat restore --write
```

They stop with a clear message if Python is missing or if `tangerine.py` is not
sitting next to them, instead of failing halfway.

`optimize-as-root.sh` prints what it is about to do before the password prompt,
and warns you if `/etc/hosts` is a symlink (it is in some containers, which
changes which file actually gets written). It uses `sudo`, falls back to `doas`,
and if neither exists it tells you the exact `su -c` command to run instead.

**Line endings matter, and they are opposite per platform.** Both files are
pinned in `.gitattributes`, guarded by tests, and documented in `.editorconfig`:

| File | Must be | Otherwise |
|---|---|---|
| `optimize-as-root.sh` | LF | bash chokes on the shebang: `\r: command not found` |
| `optimize-as-admin.bat` | CRLF | cmd.exe mis-parses the file and can exit silently |

---

## What changes between platforms

Portability is not just a different file path. These are the things that actually
bite on each platform, and all of them are handled:

### Linux

**1. The order in `/etc/nsswitch.conf`.** The most easily missed one: if the
`hosts:` line reads `dns files`, or has no `files` at all, then nothing you write
to `/etc/hosts` will ever be consulted — glibc asks DNS first. The tool reads this
file before starting and warns you if the order is wrong. The healthy form is:

```
hosts:          files mdns4_minimal [NOTFOUND=return] dns
```

**2. IPv6 stealing the route.** The subtler one. If the machine has IPv6 enabled
(and holds a global address), RFC 3484 makes the stack prefer it — but GitHub's
IPv6 is usually unreachable. So a perfectly good IPv4 entry in hosts does nothing,
because every request stalls on IPv6 first. The tool detects the combination
"global IPv6 present" + "GitHub's IPv6 unreachable" and tells you to append one
line to `/etc/gai.conf`:

```
precedence ::ffff:0:0/96  100
```

**3. Too many DNS cache daemons.** They are tried in order and the first working
one wins:

| Cache service | Command |
|---|---|
| systemd-resolved | `resolvectl flush-caches` |
| systemd-resolved (older) | `systemd-resolve --flush-caches` |
| nscd | `nscd -i hosts` |
| none of the above | no flush needed, `/etc/hosts` is read directly |

**4. Container environments.** If `/.dockerenv` exists, or the cgroup contains
docker/k8s markers, it warns that changes to `/etc/hosts` are lost when the
container is rebuilt and may be overwritten by the orchestrator. That case belongs
on the host, or in Docker's `--add-host`.

**5. Line endings.** Linux and macOS get LF, Windows gets CRLF. Without this, a
stray `\r` makes some programs fail to parse the file.

### Windows

**Writing hosts requires administrator rights**, and a non-elevated run is refused
up front rather than half-writing the file. Double-clicking `optimize-as-admin.bat`
raises the UAC prompt for you. `ipconfig /flushdns` runs automatically afterwards.

### macOS

Cache flushing tries `dscacheutil -flushcache` then `killall -HUP mDNSResponder`.
The code path exists and is exercised by the unit tests, but has **not been
verified on real hardware** — tell me if it misbehaves.

---

## What the three commands do

### `resolve` — cross-checking DNS sources

It queries the same domain through **9 DNS sources** at once: 7 over raw UDP/53
(the wire format is built by hand, bypassing the system resolver entirely) and 2
over DoH/HTTPS. It lists the A records each one returns, then gives a verdict.

Both signatures of poisoning are recognized:

| Signature | Appearance | Real example |
|---|---|---|
| Unusable answers | `127.0.0.1` / `0.0.0.0` / private or reserved ranges | flagged `[polluted]` |
| Cross-source divergence | every source returns a different IP | `github.global.ssl.fastly.net` yielded 6 completely different addresses, best consensus only 2/8 |

For a mainstream name like `github.com` all sources currently agree exactly —
meaning the main site's resolution is clean, and the slowness is **not** a DNS
problem. Worth knowing before you spend an evening editing hosts.

### `probe` — measuring every IP

Measuring TCP latency alone is not enough. What is common on a mainland-China
uplink is this: TCP connects instantly, but the TLS handshake gets RST, or it
completes with somebody else's certificate. So each candidate IP goes through three
steps:

1. **TCP handshake timing**
2. **TLS handshake with full certificate verification** (`check_hostname=True`) — only this earns `verified`
3. On failure, retry without verification: if it handshakes, the certificate is merely wrong (a middlebox); if it does not, the address is a black hole

Three outcomes:

- `verified` — the certificate really is GitHub's, safe to use
- `cert mismatch` — TLS works but the certificate is wrong, **rejected**; this is a hijacking signature
- `unreachable` — not even the handshake completes

A real sample: `185.199.111.133` answered TCP in 75 ms, the fastest on the board,
with a mismatched certificate. Any tool that sorts by TCP latency alone will walk
straight into that.

### `optimize` — writing hosts

The best verified IP per domain goes into a managed block:

```
# >>> tangerine managed block begin
# generated by tangerine 1.0.0 at 2026-10-07 23:14:02
20.205.243.166  github.com
185.199.108.133 raw.githubusercontent.com
# github.com -> 20.205.243.166  (204 ms)
# <<< tangerine managed block end
```

After writing, the DNS cache is flushed and every domain is re-checked once.

---

## How the "best" IP is chosen

**Stability, then cross-source consensus, then latency.** Not "the fastest".

Every IP is sampled 3 times (`--rounds`) and the number of rounds where full
verification passed is recorded. The reason is practical: the path from mainland
China to GitHub flaps badly, and it is normal for one IP to answer in 60 ms one
round and time out the next. A real observation: an address was the fastest at
47 ms in a single round but succeeded in only 1 of 3 — write that into hosts and
you have bought yourself random stalls.

Cross-source consensus is how many resolvers independently returned that IP. An
address only one source knows about does not deserve much trust.

---

## Options

```bash
--timeout 2.5         per-handshake timeout in seconds (default 2.5)
--rounds 3            samples per IP (default 3)
--workers 12          IP-level concurrency (default 12)
--domain-parallel 3   domain-level concurrency, 1 for serial (default 3)
--domains github.com api.github.com     only handle these domains
--json                also print a JSON report
--extra-ip github.com=140.82.112.3      add a candidate IP by hand, repeatable
```

The full 8-domain run takes about **19 seconds** with default settings.

`--extra-ip` is the emergency exit: if DNS is completely poisoned and no candidate
can be discovered at all, you can feed IPs in and let the tool measure them.
**Do not copy IP lists off the internet** — your machine being able to ping an
address says nothing about whether your egress takes the same route. Measure first,
then write.

---

## Safety design

Anything that touches a system file is done the most conservative way possible:

- **Automatic backup** — hosts is copied to `hosts.tangerine-backup-YYYYmmdd-HHMMSS.bak` in the same directory before every write
- **Block isolation** — only the region between `MARK_BEGIN` and `MARK_END` is touched; every other entry you have is left alone to the byte
- **Lossless round-trip** — hosts is read and written with `surrogateescape`, so even non-UTF-8 bytes survive unchanged and your existing comments are never mangled
- **Idempotent** — running it repeatedly never stacks up multiple blocks
- **Preview before acting** — `restore` only previews unless you add `--write`; same for `optimize --dry-run`
- **Privilege gate** — an unprivileged run is refused outright with the correct elevation command for the platform, instead of failing halfway through a write

After `restore`, hosts is byte-for-byte identical to what it was before. That is
covered by tests, on both the Windows and Linux line-ending paths.

---

## Project layout

```
tangerine-github-access/
├── tangerine.py                  the whole tool, one file
├── optimize-as-admin.bat         Windows launcher (self-elevating via UAC)
├── optimize-as-root.sh           Linux/macOS launcher (self-elevating via sudo)
├── tests/
│   └── test_tangerine.py         42 tests, stdlib unittest
├── .github/workflows/ci.yml      CI: 3 OS x 2 Python versions
├── .gitattributes                pins LF for .sh and CRLF for .bat
├── .editorconfig
├── CHANGELOG.md
├── LICENSE                       MIT
└── README.md
```

---

## Testing

```bash
python -m unittest discover -s tests -v
```

42 tests, no test runner to install. They never touch the real hosts file —
everything that writes goes to a temporary file — and the platform globals are
patched so the Linux and macOS branches can be exercised from any machine.

What is covered: DNS wire-format encoding and parsing (including compression
pointers and error rcodes), IP filtering, the candidate scoring order, hosts
block rendering and stripping, backup naming, LF/CRLF selection per platform,
byte-for-byte round-tripping of non-UTF-8 content, idempotency, and the
`nsswitch.conf` parser.

CI runs the suite on **Ubuntu, Windows and macOS** across Python 3.9 and 3.13,
which is also how the Linux and macOS code paths get verified on real systems.

---

## Troubleshooting

**It says "no IP passed certificate verification" for a domain.**
Every candidate for that domain was rejected, so nothing was written for it.
That is the intended behaviour — better a missing entry than a poisoned one.
Common causes: that specific IP is being blocked (it happens per-IP inside a
`/24`, not per-subnet), or DNS returned only addresses that are not real GitHub
endpoints. Re-run later; the set of usable IPs changes.

**`doh://cf` and `udp://1.1.1.1` always fail.**
Expected in mainland China — Cloudflare's DoH and `1.1.1.1` are unreachable.
They are dropped after two failures so they stop costing you time, and the
remaining 7 sources are plenty.

**`github.global.ssl.fastly.net` is always skipped.**
Also expected. It is a legacy domain GitHub barely uses now, and it is the most
heavily poisoned one — no two sources agree on it.

**Everything works but the speed did not change.**
Then DNS was not your bottleneck. Use `resolve` to see whether the answers are
consistent; if they are, the problem is on the wire (packet loss, congestion at
peak hours) and hosts cannot fix it — you need a proxy or a better route.

**I am on Linux and hosts entries seem to be ignored.**
Check the two Linux traps above: the `hosts:` order in `/etc/nsswitch.conf`, and
whether IPv6 is enabled while GitHub's IPv6 is unreachable. The tool reports
both, but if you skipped the output, that is where to look.

---

## Caveats

**Literal IPs in hosts go stale.** GitHub's addresses shift with Azure / Fastly
scheduling. Re-run `optimize` every couple of weeks, on a schedule:

Windows (Win + R, `taskschd.msc`, weekly trigger):

```
python tangerine.py restore --write && python tangerine.py optimize
```

Linux / macOS (`crontab -e`, every Monday at 03:00):

```cron
0 3 * * 1 /usr/bin/python3 /path/to/tangerine.py restore --write && /usr/bin/python3 /path/to/tangerine.py optimize
```

Note that cron has a very sparse `PATH`; things like `resolvectl` often live in
`/usr/sbin`, so use full paths if needed. Cron also has no terminal, so `sudo`
will need a `NOPASSWD` entry or you should run the scheduled job as root.

Two boundaries worth stating plainly:

- **hosts only fixes resolution.** If the bottleneck is packet loss across the border (peak hours), hosts will not help — that needs a proxy.
- **This tool changes nothing about how your traffic is routed or encrypted.** It reads public DNS records, measures reachability, and writes the result into your own hosts file. That is all.

---

## Sample output

```
tangerine resolve - multi-source DNS cross-check
Compares the A records every source returns. 127.0.0.1 / 0.0.0.0 / private ranges mean that source is poisoned.

github.com
  doh://alidns           ok         20.205.243.166
  doh://cf               no answer  URLError: <urlopen error timed out>
  doh://dnspod           ok         20.205.243.166
  udp://1.1.1.1          no answer  TimeoutError: timed out
  udp://114.114.114.114  ok         20.205.243.166
  udp://119.29.29.29     ok         20.205.243.166
  consensus all 8 sources agree: 20.205.243.166

raw.githubusercontent.com
  185.199.108.133  tcp    70.9ms  tls    88.8ms  ok 1/3  src 7/7  verified
  185.199.110.133  tcp    49.7ms  tls   127.7ms  ok 1/3  src 7/7  verified
  185.199.111.133  tcp         -  tls         -  ok 0/2  src 7/7  unreachable  tcp: TimeoutError
  185.199.109.133  tcp    83.7ms  tls         -  ok 0/2  src 6/7  unreachable  tcp: TimeoutError
  picked   185.199.108.133  (tcp 71 + tls 89 = 160 ms, ok 1/3, 7 sources agree)
```

`doh://cf` (Cloudflare DoH) timing out and `udp://1.1.1.1` timing out are both
expected. Once detected, they are dropped for the rest of the run — otherwise every
domain pays their timeout again.

---

## License

[MIT](LICENSE) © 2026 Jingyi Lin
