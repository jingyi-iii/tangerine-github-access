# Changelog

Notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-07

First release.

### Added

- `resolve` — queries 9 DNS sources (7 over raw UDP/53, 2 over DoH) and reports
  the A records each one returns, flagging both signatures of poisoning:
  unusable answers (`127.0.0.1`, private ranges) and cross-source divergence.
- `probe` — measures each candidate IP with a TCP handshake plus a TLS
  handshake, verifying the certificate chain and hostname. Candidates that
  handshake but present the wrong certificate are rejected as middleboxes.
  Every IP is sampled several times and scored by **stability → cross-source
  consensus → latency**, never by raw speed alone.
- `optimize` — picks a winner per domain and writes it into a managed block in
  the hosts file, with an automatic backup, a DNS cache flush, and a
  post-write re-check.
- `restore` — removes the managed block. Previews by default; `--write` acts.
- `show` — prints the current managed block.
- Per-platform launchers: `optimize-as-admin.bat` (self-elevating through UAC)
  and `optimize-as-root.sh` (self-elevating through `sudo`, falling back to
  `doas`).
- Linux pre-flight checks: the `hosts:` lookup order in `/etc/nsswitch.conf`,
  and the "IPv6 enabled but GitHub's IPv6 unreachable" trap that silently
  defeats any hosts entry.
- Container detection, with a warning that `/etc/hosts` changes do not survive
  a rebuild.

### Notes

- Standard library only. No dependencies to install.
- Writing the hosts file needs administrator rights on Windows and `root` on
  Linux/macOS. Every write is backed up first, and a non-privileged run is
  refused outright rather than failing halfway.
- Line endings are load-bearing: `.sh` must be LF, `.bat` must be CRLF. Both
  are pinned in `.gitattributes` and guarded by tests.
