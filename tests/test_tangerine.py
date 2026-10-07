"""Unit tests for tangerine.py.

Standard library only, no test runner to install:

    python -m unittest discover -s tests -v

The tests deliberately avoid touching the real hosts file. Everything that
writes goes to a temporary file, and the platform globals are patched so the
Linux and macOS branches can be exercised from any machine.
"""

import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tangerine as t  # noqa: E402


class PlatformPatchMixin:
    """Patch the module-level platform globals and restore them afterwards.

    Mix this in *before* unittest.TestCase and let super() drive setUp/tearDown.
    """

    _GLOBALS = ("IS_WIN", "IS_MAC", "IS_LINUX", "NEWLINE")

    def setUp(self):
        super().setUp()
        self._saved = {name: getattr(t, name) for name in self._GLOBALS}

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(t, name, value)
        super().tearDown()

    def patch_platform(self, *, win=False, mac=False, linux=False, newline=None):
        t.IS_WIN = win
        t.IS_MAC = mac
        t.IS_LINUX = linux
        t.NEWLINE = newline if newline is not None else ("\r\n" if win else "\n")


class TestNsswitchCheck(unittest.TestCase):
    """check_nsswitch decides whether writing hosts will have any effect."""

    def test_files_before_dns_is_fine(self):
        self.assertEqual(t.check_nsswitch("hosts: files dns\n"), "")
        self.assertEqual(
            t.check_nsswitch("hosts: files mdns4_minimal [NOTFOUND=return] dns\n"), "")

    def test_dns_before_files_is_rejected(self):
        msg = t.check_nsswitch("hosts: dns files\n")
        self.assertIn("comes before", msg)
        self.assertIn("hosts: dns files", msg)

    def test_missing_files_is_rejected(self):
        msg = t.check_nsswitch("hosts: myhostname dns\n")
        self.assertIn('no "files"', msg)

    def test_commented_line_is_ignored(self):
        self.assertEqual(t.check_nsswitch("# hosts: dns files\nhosts: files dns\n"), "")

    def test_no_hosts_line_at_all(self):
        self.assertEqual(t.check_nsswitch("passwd: files\ngroup: files\n"), "")

    def test_empty_input(self):
        self.assertEqual(t.check_nsswitch(""), "")


class TestIpFiltering(unittest.TestCase):
    def test_accepts_public_addresses(self):
        for ip in ("20.205.243.166", "185.199.108.133", "8.8.8.8"):
            with self.subTest(ip=ip):
                self.assertTrue(t.is_usable_ip(ip))

    def test_rejects_poisoning_shapes(self):
        for ip in ("127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.1.1",
                   "172.16.0.1", "169.254.1.1", "100.64.0.1", "224.0.0.1"):
            with self.subTest(ip=ip):
                self.assertFalse(t.is_usable_ip(ip))

    def test_rejects_garbage(self):
        self.assertFalse(t.is_usable_ip("not-an-ip"))
        self.assertFalse(t.is_usable_ip(""))


class TestDnsWireFormat(unittest.TestCase):
    def test_query_encodes_labels(self):
        tid, packet = t._build_query("github.com")
        self.assertIsInstance(tid, int)
        self.assertEqual(packet, struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
                         + b"\x06github\x03com\x00" + struct.pack(">HH", 1, 1))

    def test_skip_name_plain(self):
        buf = b"\x03www\x00rest"
        self.assertEqual(t._skip_name(buf, 0), 5)

    def test_skip_name_compression_pointer(self):
        buf = b"\xc0\x0crest"
        self.assertEqual(t._skip_name(buf, 0), 2)

    def test_parse_a_record_with_compressed_name(self):
        tid, _ = t._build_query("example.com")
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                  + socket.inet_aton("93.184.216.34"))
        response = (struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0)
                    + question + answer)
        self.assertEqual(t._parse_answers(response), ["93.184.216.34"])

    def test_parse_multiple_answers(self):
        tid, _ = t._build_query("example.com")
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        answers = b"".join(
            b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
            for ip in ("1.2.3.4", "5.6.7.8"))
        response = (struct.pack(">HHHHHH", tid, 0x8180, 1, 2, 0, 0)
                    + question + answers)
        self.assertEqual(t._parse_answers(response), ["1.2.3.4", "5.6.7.8"])

    def test_non_zero_rcode_raises(self):
        # NXDOMAIN (rcode 3)
        response = struct.pack(">HHHHHH", 1, 0x8183, 1, 0, 0, 0)
        with self.assertRaises(ValueError):
            t._parse_answers(response)

    def test_short_header_raises(self):
        with self.assertRaises(ValueError):
            t._parse_answers(b"\x00\x01")


def _probe(ip, verified_rounds, attempts, consensus, latency):
    p = t.Probe(host="github.com", ip=ip, attempts=attempts,
                verified_rounds=verified_rounds, consensus=consensus)
    p.tcp_ms = latency
    p.tls_ms = 0.0
    return p


class TestProbeScoring(unittest.TestCase):
    def test_stability_beats_latency(self):
        """A flapping 50 ms IP must lose to a steady 200 ms one."""
        flappy = _probe("1.1.1.1", verified_rounds=1, attempts=3,
                        consensus=8, latency=50.0)
        steady = _probe("2.2.2.2", verified_rounds=3, attempts=3,
                        consensus=8, latency=200.0)
        self.assertEqual(t.pick_best([flappy, steady]).ip, "2.2.2.2")

    def test_consensus_breaks_ties(self):
        lonely = _probe("1.1.1.1", 3, 3, consensus=1, latency=100.0)
        popular = _probe("2.2.2.2", 3, 3, consensus=7, latency=100.0)
        self.assertEqual(t.pick_best([lonely, popular]).ip, "2.2.2.2")

    def test_latency_breaks_remaining_ties(self):
        slow = _probe("1.1.1.1", 3, 3, consensus=7, latency=300.0)
        fast = _probe("2.2.2.2", 3, 3, consensus=7, latency=100.0)
        self.assertEqual(t.pick_best([slow, fast]).ip, "2.2.2.2")

    def test_unverified_is_never_picked(self):
        bad = _probe("1.1.1.1", 0, 3, consensus=8, latency=10.0)
        good = _probe("2.2.2.2", 1, 3, consensus=1, latency=900.0)
        self.assertEqual(t.pick_best([bad, good]).ip, "2.2.2.2")

    def test_no_verified_candidates_returns_none(self):
        self.assertIsNone(t.pick_best([_probe("1.1.1.1", 0, 3, 8, 10.0)]))

    def test_probe_properties(self):
        p = _probe("1.1.1.1", verified_rounds=2, attempts=4,
                   consensus=3, latency=120.0)
        p.tls_ms = 30.0
        self.assertTrue(p.verified)
        self.assertTrue(p.usable)
        self.assertAlmostEqual(p.stability, 0.5)
        self.assertAlmostEqual(p.latency, 150.0)

    def test_zero_attempts_does_not_divide_by_zero(self):
        p = t.Probe(host="h", ip="1.1.1.1", attempts=0)
        self.assertEqual(p.stability, 0.0)

    def test_to_dict_round_trip_of_derived_fields(self):
        p = _probe("1.1.1.1", 2, 4, 3, 100.0)
        d = p.to_dict()
        self.assertEqual(d["ip"], "1.1.1.1")
        self.assertTrue(d["usable"])
        self.assertEqual(d["stability"], 0.5)
        self.assertEqual(d["latency_ms"], 100.0)


class TestExtraIpParsing(unittest.TestCase):
    def test_parses_repeated_hosts(self):
        parsed = t._parse_extra_ips(
            ["github.com=1.1.1.1", "github.com=2.2.2.2", "api.github.com=3.3.3.3"])
        self.assertEqual(parsed["github.com"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(parsed["api.github.com"], ["3.3.3.3"])

    def test_ignores_malformed_entries(self):
        self.assertEqual(t._parse_extra_ips(["nonsense", "", "a="]), {"a": [""]})

    def test_none_input(self):
        self.assertEqual(t._parse_extra_ips(None), {})


class TestHostsBlock(PlatformPatchMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp()) / "hosts"
        self.tmp.write_bytes(b"# original\n127.0.0.1 localhost\n")
        self.entries = [("github.com", "20.205.243.166", 204.0),
                        ("api.github.com", "20.205.243.168", 206.0)]

    def tearDown(self):
        for f in self.tmp.parent.glob("*"):
            os.remove(f)
        os.rmdir(self.tmp.parent)
        super().tearDown()

    def test_render_block_contains_markers_and_entries(self):
        block = t.render_block(self.entries)
        self.assertTrue(block.startswith(t.MARK_BEGIN))
        self.assertTrue(block.endswith(t.MARK_END))
        self.assertIn("20.205.243.166", block)
        self.assertIn("github.com", block)

    def test_strip_block_removes_only_the_block(self):
        original = t.read_hosts(self.tmp)
        merged = t.strip_block(original + "\n\n" + t.render_block(self.entries) + "\n")
        self.assertEqual(merged, original.strip("\n"))

    def test_strip_block_is_noop_without_block(self):
        text = "# original\n127.0.0.1 localhost"
        self.assertEqual(t.strip_block(text), text)

    def test_strip_block_leaves_unrelated_entries_alone(self):
        text = ("127.0.0.1 view-localhost\n" + t.MARK_BEGIN + "\n"
                + "1.2.3.4 github.com\n" + t.MARK_END + "\n10.0.0.1 internal\n")
        result = t.strip_block(text)
        self.assertIn("127.0.0.1 view-localhost", result)
        self.assertIn("10.0.0.1 internal", result)
        self.assertNotIn("1.2.3.4", result)

    def test_write_hosts_uses_crlf_on_windows(self):
        self.patch_platform(win=True)
        t.write_hosts("a\nb\n", self.tmp)
        raw = self.tmp.read_bytes()
        self.assertIn(b"a\r\nb\r\n", raw)
        self.assertNotIn(b"\n\n", raw)

    def test_write_hosts_uses_lf_on_unix(self):
        self.patch_platform(linux=True)
        t.write_hosts("a\nb\n", self.tmp)
        raw = self.tmp.read_bytes()
        self.assertEqual(raw, b"a\nb\n")
        self.assertNotIn(b"\r", raw)

    def test_write_hosts_appends_final_newline(self):
        self.patch_platform(linux=True)
        t.write_hosts("a\nb", self.tmp)
        self.assertTrue(self.tmp.read_bytes().endswith(b"\n"))

    def test_backup_is_created_with_expected_name(self):
        self.patch_platform(linux=True)
        backup = t.write_hosts("x\n", self.tmp)
        self.assertTrue(backup.exists())
        self.assertIn(f"{t.APP}-backup-", backup.name)
        self.assertEqual(backup.read_bytes(), b"# original\n127.0.0.1 localhost\n")

    def test_round_trip_preserves_non_utf8_bytes(self):
        """The user's existing entries must survive byte for byte."""
        original = b"# original\n127.0.0.1 localhost\n\xff\xfe legacy encoding\n"
        self.tmp.write_bytes(original)
        self.patch_platform(linux=True)

        merged = t.strip_block(t.read_hosts(self.tmp))
        t.write_hosts(merged + "\n\n" + t.render_block(self.entries) + "\n", self.tmp)

        self.assertIn(b"\xff\xfe legacy encoding", self.tmp.read_bytes())
        restored = t.strip_block(t.read_hosts(self.tmp)).strip()
        self.assertEqual(restored, t.strip_block(t.decode_hosts(original)).strip())

    def test_repeated_writes_do_not_stack_blocks(self):
        self.patch_platform(linux=True)
        for _ in range(3):
            merged = t.strip_block(t.read_hosts(self.tmp))
            t.write_hosts(merged + "\n\n" + t.render_block(self.entries) + "\n", self.tmp)
        self.assertEqual(t.read_hosts(self.tmp).count(t.MARK_BEGIN), 1)


class TestFlushCandidates(PlatformPatchMixin, unittest.TestCase):
    def test_windows(self):
        self.patch_platform(win=True)
        self.assertEqual(t._flush_candidates(), [["ipconfig", "/flushdns"]])

    def test_macos_tries_dscacheutil_first(self):
        self.patch_platform(mac=True)
        cmds = t._flush_candidates()
        self.assertEqual(cmds[0], ["dscacheutil", "-flushcache"])
        self.assertIn("mDNSResponder", cmds[1][-1])

    def test_linux_covers_resolved_and_nscd(self):
        self.patch_platform(linux=True)
        names = [c[0] for c in t._flush_candidates()]
        self.assertEqual(names[0], "resolvectl")
        self.assertIn("systemd-resolve", names)
        self.assertIn("nscd", names)


class TestDbHelpers(unittest.TestCase):
    def test_decode_hosts_keeps_undecodable_bytes(self):
        raw = b"\xff\xfe"
        self.assertEqual(t.decode_hosts(raw).encode("utf-8", "surrogateescape"), raw)

    def test_read_hosts_missing_file(self):
        missing = Path(tempfile.gettempdir()) / "__tangerine_no_such_file__"
        self.assertEqual(t.read_hosts(missing), "")


class TestRepositoryLineEndings(unittest.TestCase):
    """Regression guard for a real bug.

    An LF-only .bat makes cmd.exe mis-parse the file and exit silently, and a
    CRLF .sh makes bash choke on the shebang. The two requirements are
    opposites, so assert both rather than trusting the editor.
    """

    ROOT = Path(__file__).resolve().parent.parent

    def _read(self, name):
        return (self.ROOT / name).read_bytes()

    def test_shell_scripts_use_lf(self):
        raw = self._read("optimize-as-root.sh")
        self.assertNotIn(b"\r", raw, "optimize-as-root.sh must use LF line endings")
        self.assertTrue(raw.startswith(b"#!/usr/bin/env bash\n"),
                        "shebang must be on a clean first line")

    def test_batch_file_uses_crlf(self):
        raw = self._read("optimize-as-admin.bat")
        crlf = raw.count(b"\r\n")
        bare_lf = raw.count(b"\n") - crlf
        self.assertGreater(crlf, 0, "optimize-as-admin.bat must use CRLF line endings")
        self.assertEqual(bare_lf, 0, f"optimize-as-admin.bat has {bare_lf} bare LF line(s)")

    def test_python_and_docs_use_lf(self):
        for name in ("tangerine.py", "README.md", "LICENSE"):
            with self.subTest(file=name):
                self.assertNotIn(b"\r", self._read(name), f"{name} must use LF")

    def test_gitattributes_pins_the_rule(self):
        text = self._read(".gitattributes").decode("utf-8")
        self.assertIn("*.bat text eol=crlf", text)
        self.assertIn("*.sh", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
