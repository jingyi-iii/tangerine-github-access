# tangerine-github-access

Find out why GitHub is slow on your machine, and fix the part of it that a hosts file can
actually fix.

One file, `tangerine.py`. Python 3.9 or newer, standard library only, no `pip install`.
Windows, Linux and macOS.

## Install

```bash
git clone https://github.com/jingyi-iii/tangerine-github-access.git
cd tangerine-github-access
python tangerine.py resolve
```

Writing the hosts file needs administrator or `root`; everything else runs unprivileged. The
launchers handle the elevation and take the same flags and subcommands as the tool itself.

| Platform | Elevate with |
| --- | --- |
| Windows | `optimize-as-admin.bat` |
| Linux / macOS | `./optimize-as-root.sh` |

## Use

```bash
python tangerine.py resolve                # is DNS poisoned? read-only
python tangerine.py probe                  # measure every candidate IP, still read-only
python tangerine.py optimize               # measure and write hosts (needs privileges)
python tangerine.py restore                # preview what would be removed
python tangerine.py restore --write        # actually remove it

./optimize-as-root.sh --dry-run            # measure only, elevated
./optimize-as-root.sh restore --write      # undo, elevated
```

A full 8-domain run takes about 19 seconds. Useful flags:

```bash
--domains github.com api.github.com     # only handle these domains
--timeout 2.5   --rounds 3   --workers 12   --domain-parallel 3
--json                                  # also print a JSON report
--extra-ip github.com=140.82.112.3      # add a candidate IP by hand, repeatable
```

## How it works

GitHub being slow is four problems stacked, and only the first is hosts' job:

```
DNS poisoning  ->  SNI / RST  ->  cross-border congestion  ->  CDN & git protocol
   resolve          probe               probe                      probe
```

`resolve` asks 9 DNS sources the same question, 7 over raw UDP/53 and 2 over DoH, and flags
both signatures of poisoning: unusable answers such as `127.0.0.1`, and sources that disagree
with each other.

`probe` measures each candidate IP in three steps: TCP handshake timing, then a TLS handshake
with full certificate verification, then a retry without verification to tell a wrong
certificate from a black hole. An address that accepts TCP and then presents somebody else's
certificate is a middlebox, and sorting by TCP latency alone picks it every time.

`optimize` writes the best verified IP per domain into a block between `MARK_BEGIN` and
`MARK_END`, then flushes the DNS cache and re-checks. Hosts is backed up to
`hosts.tangerine-backup-YYYYmmdd-HHMMSS.bak` first, nothing outside that block is touched, and
`restore` is byte-for-byte reversible.

## Notes

Hosts only fixes resolution. If the bottleneck is packet loss across the border, you need a
proxy. Literal IPs go stale as GitHub's addresses shift, so re-run `optimize` every couple of
weeks:

```cron
0 3 * * 1 /usr/bin/python3 /path/to/tangerine.py restore --write && /usr/bin/python3 /path/to/tangerine.py optimize
```

On Linux, two things silently defeat a hosts entry. If the `hosts:` line in
`/etc/nsswitch.conf` reads `dns files`, or has no `files` at all, glibc asks DNS first and
never consults `/etc/hosts`; the healthy form is
`hosts: files mdns4_minimal [NOTFOUND=return] dns`. And with IPv6 enabled and a global address
held, RFC 3484 makes the stack prefer it while GitHub's IPv6 is usually unreachable, so every
request stalls there first; the fix is `precedence ::ffff:0:0/96  100` in `/etc/gai.conf`. The
tool checks both and tells you.

Do not copy IP lists off the internet. Your machine being able to reach an address says nothing
about whether your egress takes the same route.

## License

MIT
