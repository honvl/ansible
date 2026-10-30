"""Offline policy-preservation, DNS failure, and API transaction checks."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import clearpass_acl_dns as acl


BEFORE = ("remark printer services\n"
          "permit tcp any host 10.10.10.10 eq 443\n"
          "permit ip any 172.16.0.0 0.15.255.255\n")
OLD = ("permit tcp any host 13.193.137.162 eq 443\n"
       "permit tcp any host 13.193.137.163 eq 443\n"
       "permit tcp any host 52.69.224.204 eq 443\n"
       "permit tcp any host 52.69.224.205 eq 443\n")
AFTER = ("permit tcp any host 192.168.1.1 eq 443\n"
         "permit udp any any eq 53\n"
         "deny ip any any")
CURRENT = BEFORE + OLD + AFTER
ANSWERS = {acl.HOSTS[0]: ["13.193.137.170", "13.193.137.171"],
           acl.HOSTS[1]: ["52.69.224.210", "52.69.224.211"]}


def profile():
    return {"id": 123, "name": acl.PROFILE, "type": "RADIUS", "action": "Accept",
            "description": "Preserve me", "_links": {"self": {"href": "/api/enforcement-profile/123"}},
            "attributes": [
                {"type": "Radius:IETF", "name": "Session-Timeout", "value": "3600"},
                {"type": acl.ATTRIBUTE_TYPE, "name": acl.ATTRIBUTE_NAME, "value": CURRENT},
                {"type": "Radius:Cisco", "name": "Cisco-AVPair", "value": "other=value"}]}


class FakeClient:
    def __init__(self):
        self.value = profile()
        self.calls = []
        self.before_patch = None
        self.bad_readback = False
        self.render_html = False

    def response(self):
        value = copy.deepcopy(self.value)
        if self.render_html:
            value["attributes"][1]["value"] = value["attributes"][1]["value"].replace("\n", "<br>")
        return value

    def profile(self, name):
        assert name == self.value["name"]
        return self.response()

    def request(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == "PATCH":
            if self.before_patch:
                self.before_patch()
            if not self.bad_readback:
                self.value.update(copy.deepcopy(body))
            return {}
        return self.response()


class RewriteTests(unittest.TestCase):
    def test_reported_clearpass_rule_matches(self):
        value = "permit tcp any host 35.75.113.120 eq 443"
        self.assertEqual(acl.cloud_block(value)[3][0][1][2], "35.75.113.120")

    def test_replaces_all_four_and_preserves_every_other_byte(self):
        result = acl.rewrite_acl(CURRENT, ANSWERS)
        self.assertTrue(result.startswith(BEFORE))
        self.assertTrue(result.endswith(AFTER))
        self.assertNotIn("13.193.137.162", result)
        self.assertNotIn("52.69.224.205", result)
        middle = result[len(BEFORE):-len(AFTER)]
        self.assertEqual(len(middle.splitlines()), 4)
        for address in sum(ANSWERS.values(), []):
            self.assertIn("permit tcp any host " + address + " eq 443\n", middle)

    def test_combines_answers_removes_duplicates_and_varies_count(self):
        for count in (1, 2, 3, 6):
            with self.subTest(count=count):
                addresses = ["13.193.137." + str(i + 1) for i in range(count)]
                result = acl.rewrite_acl(CURRENT, {acl.HOSTS[0]: addresses, acl.HOSTS[1]: addresses})
                self.assertEqual(len(acl.cloud_block(result)[3]), count)
                self.assertEqual(acl.rewrite_acl(result, {"both": list(reversed(addresses))}), result)

    def test_no_change_preserves_order_case_and_spacing(self):
        current = CURRENT.replace("permit tcp any host 13", "Permit  tcp any host 13")
        old_ips = [m[2] for _, m in acl.cloud_block(current)[3]]
        self.assertEqual(acl.rewrite_acl(current, {"both": old_ips[::-1]}), current)

    def test_crlf_normalized_and_missing_terminal_newline_preserved(self):
        for current in (CURRENT.replace("\n", "\r\n"), OLD.rstrip("\n")):
            result = acl.rewrite_acl(current, ANSWERS)
            self.assertEqual(result.endswith("\n"), current.endswith("\n"))
            self.assertNotIn("\r", result)
            self.assertIn("\n", result)

    def test_html_break_variants_become_real_newlines_preserving_unmanaged_rules(self):
        for separator in ("<br>", "<br/>", "<br />", "<BR>", "<Br />\r\n", "<br>\n", "<br> \r\n"):
            with self.subTest(separator=separator):
                current = CURRENT.replace("\n", separator)
                result = acl.rewrite_acl(current, ANSWERS)
                self.assertTrue(result.startswith(BEFORE))
                self.assertTrue(result.endswith(AFTER))
                self.assertEqual(result, acl.rewrite_acl(CURRENT, ANSWERS))
                self.assertNotIn("<br", result.lower())
                self.assertNotIn(r"\n", result)
                self.assertEqual(len(acl.cloud_block(result)[3]), 4)
                self.assertEqual(acl.rewrite_acl(result, ANSWERS), result)

    def test_mixed_separators_and_rule_count_change(self):
        prefix = BEFORE.replace("\n", "<br />\r\n")
        suffix = AFTER.replace("\n", "<BR>")
        block = OLD.replace("\n", "<br>")
        current = prefix + block + suffix
        for count in (1, 3, 6):
            with self.subTest(count=count):
                addresses = ["35.75.113." + str(i + 1) for i in range(count)]
                result = acl.rewrite_acl(current, {"both": addresses})
                self.assertEqual(result, BEFORE + "".join(
                    "permit tcp any host " + ip + " eq 443\n" for ip in addresses) + AFTER)

    def test_last_rule_without_terminator_uses_real_newlines(self):
        current = "permit tcp any host 10.0.0.1 eq 443<br>permit tcp any host 35.75.113.120 eq 443"
        result = acl.rewrite_acl(current, ANSWERS)
        self.assertIn("\n", result)
        self.assertNotIn("<br>", result)
        self.assertTrue(result.endswith("eq 443"))
        self.assertEqual(len(acl.cloud_block(result)[3]), 4)

    def test_html_private_rule_or_deny_between_public_rules_is_refused(self):
        for separator in ("<br>", "<br />\r\n"):
            for between in ("permit tcp any host 10.0.0.1 eq 443", "deny tcp any any eq 443"):
                current = separator.join((OLD.splitlines()[0], between, OLD.splitlines()[1]))
                with self.subTest(separator=separator, between=between), self.assertRaises(acl.UpdateError):
                    acl.rewrite_acl(current, ANSWERS)

    def test_rfc1918_boundaries(self):
        private = ("10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255")
        prefix = "".join("permit tcp any host " + ip + " eq 443\n" for ip in private)
        result = acl.rewrite_acl(prefix + OLD, ANSWERS)
        self.assertTrue(result.startswith(prefix))
        for ip in ("11.0.0.1", "172.15.255.255", "172.32.0.0", "192.169.0.1"):
            self.assertEqual(len(acl.cloud_block("permit tcp any host " + ip + " eq 443")[3]), 1)

    def test_missing_split_empty_or_invalid_blocks_refused(self):
        for current in (BEFORE + AFTER, OLD.replace("52.69.224.204", "52.69.224.404"),
                        OLD.replace("52.69.224.204", "10.1.1.1")):
            with self.subTest(current=current), self.assertRaises((acl.UpdateError, ValueError)):
                acl.rewrite_acl(current, ANSWERS)
        with self.assertRaises(acl.UpdateError):
            acl.rewrite_acl(CURRENT, {})


class DnsTests(unittest.TestCase):
    def test_all_unique_answers_are_numerically_sorted(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                   for ip in ("13.193.137.11", "13.193.137.2", "13.193.137.11")]
        with patch.object(acl.socket, "getaddrinfo", return_value=records) as lookup:
            self.assertEqual(acl.resolve_ipv4(acl.HOSTS[0]), ["13.193.137.2", "13.193.137.11"])
            lookup.assert_called_once_with(acl.HOSTS[0], None, socket.AF_INET, socket.SOCK_STREAM)

    def test_empty_error_and_nonpublic_answers_fail(self):
        with patch.object(acl.socket, "getaddrinfo", side_effect=socket.gaierror("unavailable")):
            with self.assertRaises(acl.UpdateError):
                acl.resolve_ipv4(acl.HOSTS[0])
        for addresses in ([], ["10.0.0.1"], ["127.0.0.1"], ["169.254.1.1"], ["224.0.0.1"], ["0.0.0.0"]):
            records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in addresses]
            with self.subTest(addresses=addresses), patch.object(acl.socket, "getaddrinfo", return_value=records):
                with self.assertRaises(acl.UpdateError):
                    acl.resolve_ipv4(acl.HOSTS[0])


class InspectionTests(unittest.TestCase):
    def test_distinguishes_real_line_breaks_literal_escapes_and_html(self):
        for value, expected in (
            (OLD, {"physical_lines": 4, "newline_characters": 4, "literal_backslash_n": 0, "html_breaks": 0, "matching_https_lines": 4}),
            (OLD.replace("\n", r"\n"), {"physical_lines": 1, "newline_characters": 0, "literal_backslash_n": 4, "html_breaks": 0, "matching_https_lines": 0}),
            (OLD.replace("\n", "<br />"), {"physical_lines": 1, "newline_characters": 0, "literal_backslash_n": 0, "html_breaks": 4, "matching_https_lines": 4, "logical_lines": 4}),
        ):
            with self.subTest(value=value):
                diagnostic = acl.inspect_acl(value)
                for key, count in expected.items():
                    self.assertEqual(diagnostic[key], count)
                self.assertEqual(len(diagnostic["non_rfc1918_ip_contexts"]), 4)

    def test_inspect_never_resolves_or_writes_even_when_acl_cannot_be_parsed(self):
        client = FakeClient()
        client.value["attributes"][1]["value"] = OLD.replace("\n", r"\n")
        with patch.object(acl, "ClearPass", return_value=client), patch.object(acl, "resolve_ipv4") as resolve:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(acl.main(["--url", "https://clearpass.example.com", "--inspect"]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["mode"], "inspect")
            self.assertFalse(result["changed"])
            self.assertEqual(result["acl_diagnostics"]["literal_backslash_n"], 4)
            self.assertNotIn("other=value", output.getvalue())
            resolve.assert_not_called()
            self.assertEqual(client.calls, [])

    def test_no_match_error_includes_diagnostics_and_never_writes(self):
        client = FakeClient()
        client.value["attributes"][1]["value"] = OLD.replace("\n", r"\n")
        with patch.object(acl, "ClearPass", return_value=client):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(acl.main(["--url", "https://clearpass.example.com"]), 1)
            result = json.loads(output.getvalue())
            self.assertIn("No non-RFC1918", result["error"])
            self.assertEqual(result["acl_diagnostics"]["physical_lines"], 1)
            self.assertEqual(client.calls, [])


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.resolver = patch.object(acl, "resolve_ipv4", side_effect=lambda host: ANSWERS[host])
        self.resolver.start()
        self.addCleanup(self.resolver.stop)
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.backup = Path(self.work.name) / "before.json"

    def test_preview_never_writes(self):
        result = acl.update(self.client, acl.PROFILE)
        self.assertTrue(result["would_change"])
        self.assertFalse(result["changed"])
        self.assertEqual(self.client.calls, [])
        self.assertFalse(self.backup.exists())

    def test_apply_preserves_profile_and_attributes_and_verifies(self):
        original = copy.deepcopy(self.client.value)
        self.client.before_patch = lambda: self.assertEqual(json.loads(self.backup.read_text()), original)
        result = acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertTrue(result["changed"])
        self.assertEqual([c[0] for c in self.client.calls], ["GET", "PATCH", "GET"])
        self.assertEqual(set(self.client.calls[1][2]), {"attributes"})
        self.assertEqual(self.client.value["attributes"][0], original["attributes"][0])
        self.assertEqual(self.client.value["attributes"][2], original["attributes"][2])
        self.assertEqual(self.client.value["description"], original["description"])
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
        self.client.calls.clear()
        result = acl.update(self.client, acl.PROFILE, True)
        self.assertFalse(result["would_change"])
        self.assertEqual(self.client.calls, [])

    def test_html_api_value_apply_backup_diff_and_idempotence(self):
        current = CURRENT.replace("\n", "<br>")
        self.client.value["attributes"][1]["value"] = current
        result = acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertTrue(result["changed"])
        self.assertIn("-permit tcp any host 13.193.137.162 eq 443\n", result["diff"])
        self.assertIn("+permit tcp any host 13.193.137.170 eq 443\n", result["diff"])
        self.assertNotIn("<br>", result["diff"])
        self.assertEqual(json.loads(self.backup.read_text())["attributes"][1]["value"], current)
        saved = self.client.value["attributes"][1]["value"]
        self.assertEqual(saved, acl.rewrite_acl(CURRENT, ANSWERS))
        payload = next(body for method, _, body in self.client.calls if method == "PATCH")
        wire_value = json.loads(json.dumps(payload))["attributes"][1]["value"]
        self.assertNotIn("<br", wire_value.lower())
        self.assertNotIn(r"\n", wire_value)
        self.assertIn("\n", wire_value)
        self.client.calls.clear()
        self.assertFalse(acl.update(self.client, acl.PROFILE, True)["changed"])
        self.assertEqual(self.client.calls, [])

    def test_html_rendered_readback_verifies_and_does_not_cause_repeat_writes(self):
        self.client.render_html = True
        self.assertTrue(acl.update(self.client, acl.PROFILE, True, self.backup)["changed"])
        stored = self.client.value["attributes"][1]["value"]
        self.assertNotIn("<br>", stored)
        self.assertIn("\n", stored)
        self.client.calls.clear()
        self.assertFalse(acl.update(self.client, acl.PROFILE, True)["would_change"])
        self.assertEqual(self.client.calls, [])

    def test_force_repairs_existing_html_even_when_dns_is_unchanged(self):
        canonical = acl.rewrite_acl(CURRENT, ANSWERS)
        broken = canonical.replace("\n", "<br>")
        self.client.value["attributes"][1]["value"] = broken
        self.assertFalse(acl.update(self.client, acl.PROFILE)["would_change"])
        preview = acl.update(self.client, acl.PROFILE, force=True)
        self.assertTrue(preview["would_change"])
        self.assertFalse(preview["changed"])
        self.assertEqual(self.client.calls, [])
        result = acl.update(self.client, acl.PROFILE, True, self.backup, force=True)
        self.assertTrue(result["changed"])
        self.assertEqual(self.client.value["attributes"][1]["value"], canonical)
        self.assertEqual(json.loads(self.backup.read_text())["attributes"][1]["value"], broken)

    def test_dns_failure_at_second_host_never_patches(self):
        with patch.object(acl, "resolve_ipv4", side_effect=[ANSWERS[acl.HOSTS[0]], acl.UpdateError("DNS failed")]):
            with self.assertRaises(acl.UpdateError):
                acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertEqual(self.client.calls, [])
        self.assertFalse(self.backup.exists())

    def test_missing_backup_or_existing_backup_prevents_patch(self):
        with self.assertRaises(acl.UpdateError):
            acl.update(self.client, acl.PROFILE, True)
        self.backup.write_text("keep")
        with self.assertRaises(FileExistsError):
            acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertEqual(self.backup.read_text(), "keep")
        self.assertNotIn("PATCH", [c[0] for c in self.client.calls])

    def test_concurrent_attribute_edit_prevents_patch(self):
        initial = copy.deepcopy(self.client.value)
        self.client.profile = lambda name: initial
        self.client.value["attributes"][0]["value"] = "7200"
        with self.assertRaisesRegex(acl.UpdateError, "changed during"):
            acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertEqual([c[0] for c in self.client.calls], ["GET"])

    def test_bad_readback_fails_and_retains_backup(self):
        self.client.bad_readback = True
        with self.assertRaisesRegex(acl.UpdateError, "read-back"):
            acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertTrue(self.backup.exists())

    def test_missing_duplicate_or_wrong_attribute_refused(self):
        for attributes in ([], [self.client.value["attributes"][1]] * 2,
                           [{"type": "Other", "name": acl.ATTRIBUTE_NAME, "value": CURRENT}]):
            self.client.value["attributes"] = attributes
            with self.subTest(attributes=attributes), self.assertRaises(acl.UpdateError):
                acl.update(self.client, acl.PROFILE, True, self.backup)
        self.assertEqual(self.client.calls, [])

    def test_cli_defaults_to_preview_and_reports_errors_as_json(self):
        with patch.object(acl, "ClearPass", return_value=self.client):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(acl.main(["--url", "https://clearpass.example.com"]), 0)
            self.assertEqual(json.loads(output.getvalue())["mode"], "preview")
            self.client.value["attributes"] = []
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(acl.main(["--url", "https://clearpass.example.com"]), 1)
            self.assertIn("error", json.loads(output.getvalue()))


if __name__ == "__main__":
    unittest.main()
