#!/usr/bin/env python3
"""Refresh the public printer-cloud HTTPS dACL block using ClearPass 6.11+ REST APIs.

Standard library only. Credentials: CLEARPASS_ACCESS_TOKEN, or
CLEARPASS_CLIENT_ID + CLEARPASS_CLIENT_SECRET. All writes require --apply.
The only non-RFC1918 HTTPS host permits must form one adjacent block.
"""
import argparse
import copy
import difflib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


PROFILE = "DPW-Wired-Printer-ACL-Combined"
ATTRIBUTE_TYPE = "Radius:Cisco"
ATTRIBUTE_NAME = "Cisco-IP-Downloadable-ACL"
HOSTS = ("a01.ugwdevice.net", "b01.ugwdevice.net")
IP_PATTERN = r"[0-9]+(?:\.[0-9]+){3}"
RFC1918 = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
SEPARATOR_PATTERN = r"<br[ \t]*/?>(?:[ \t]*(?:\r\n|\n|\r))?|\r\n|\n|\r"
ACL_SEPARATOR = re.compile(SEPARATOR_PATTERN, re.I)
RULE_PATTERN = re.compile(
    r"([ \t]*permit[ \t]+tcp[ \t]+any[ \t]+host[ \t]+)(" + IP_PATTERN
    + r")([ \t]+eq[ \t]+443[ \t]*)(" + SEPARATOR_PATTERN + r")?", re.I)


class UpdateError(Exception):
    def __init__(self, message, diagnostics=None, diagnostic_key="acl_diagnostics", write_attempted=False):
        super().__init__(message)
        self.diagnostics = diagnostics
        self.diagnostic_key = diagnostic_key
        self.write_attempted = write_attempted


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UpdateError("ClearPass redirected the request; use its direct HTTPS URL")


class ClearPass:
    def __init__(self, url, ca_file=None, insecure=False, timeout=30):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise UpdateError("--url must be an HTTPS origin, e.g. https://clearpass.example.com")
        self.url = url.rstrip("/")
        self.timeout = timeout
        context = ssl.create_default_context(cafile=ca_file)
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=context))
        self.token = os.environ.get("CLEARPASS_ACCESS_TOKEN", "")
        if not self.token:
            client_id = os.environ.get("CLEARPASS_CLIENT_ID", "")
            secret = os.environ.get("CLEARPASS_CLIENT_SECRET", "")
            if not client_id or not secret:
                raise UpdateError("Set CLEARPASS_ACCESS_TOKEN or CLEARPASS_CLIENT_ID and CLEARPASS_CLIENT_SECRET")
            result = self.request("POST", "/api/oauth", {
                "grant_type": "client_credentials", "client_id": client_id,
                "client_secret": secret,
            })
            self.token = result.get("access_token", "")
            if not self.token:
                raise UpdateError("ClearPass did not return an access token")

    def request(self, method, path, body=None):
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            # Do not print response bodies: they may echo credentials or attributes.
            raise UpdateError("ClearPass {} {} failed: HTTP {}".format(method, path, exc.code)) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise UpdateError("ClearPass {} request failed: {}".format(method, exc)) from exc

    def profile(self, name):
        result = self.request("GET", "/api/enforcement-profile/name/" + urllib.parse.quote(name, safe=""))
        if not isinstance(result, dict) or result.get("name") != name:
            raise UpdateError("ClearPass returned an unexpected enforcement profile")
        if not str(result.get("id", "")).isdigit():
            raise UpdateError("Enforcement profile has no numeric ID")
        return result


def acl_index(profile):
    attributes = profile.get("attributes")
    if not isinstance(attributes, list) or not all(isinstance(a, dict) for a in attributes):
        raise UpdateError("Enforcement profile attributes must be a list of objects")
    matches = [i for i, a in enumerate(attributes)
               if a.get("type") == ATTRIBUTE_TYPE and a.get("name") == ATTRIBUTE_NAME]
    if len(matches) != 1:
        raise UpdateError("Expected exactly one {} / {} attribute; found {}".format(
            ATTRIBUTE_TYPE, ATTRIBUTE_NAME, len(matches)))
    index = matches[0]
    if not isinstance(attributes[index].get("value"), str):
        raise UpdateError("The downloadable ACL value must be a string")
    return index


def split_acl_lines(value):
    """Split newline or HTML-break-delimited ACLs, retaining every original byte."""
    lines = []
    offset = 0
    for match in ACL_SEPARATOR.finditer(value):
        lines.append(value[offset:match.end()])
        offset = match.end()
    if offset < len(value):
        lines.append(value[offset:])
    return lines


def acl_diff_lines(value):
    """Render logical rules as readable lines only for the preview diff."""
    return [ACL_SEPARATOR.sub("\n", line).rstrip("\r\n") + "\n"
            for line in split_acl_lines(value)]


def normalize_acl(value):
    """Convert API display separators to actual LF characters for the switch dACL."""
    return ACL_SEPARATOR.sub("\n", value)


def comparison_lines(value):
    """Ignore trailing horizontal whitespace and terminal blank lines, not commands/order."""
    lines = [line.rstrip(" \t") for line in normalize_acl(value).splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    return lines


def verify_attributes(expected, returned):
    """Compare ACL command text separately from all other attribute fields."""
    report = {"matches": False, "expected_attribute_count": len(expected),
              "returned_attribute_count": len(returned) if isinstance(returned, list) else None}
    try:
        expected_index = acl_index({"attributes": expected})
        returned_index = acl_index({"attributes": returned})
    except UpdateError as exc:
        report["reason"] = str(exc)
        return report
    expected_acl = expected[expected_index]["value"]
    returned_acl = returned[returned_index]["value"]
    expected_lines, returned_lines = comparison_lines(expected_acl), comparison_lines(returned_acl)
    expected_other, returned_other = copy.deepcopy(expected), copy.deepcopy(returned)
    expected_other[expected_index]["value"] = None
    returned_other[returned_index]["value"] = None
    acl_matches = expected_lines == returned_lines
    other_matches = expected_other == returned_other
    report.update(matches=acl_matches and other_matches, acl_matches=acl_matches,
                  other_attribute_fields_match=other_matches,
                  expected_acl_position=expected_index, returned_acl_position=returned_index)
    if not acl_matches:
        report["acl_diff"] = "".join(difflib.unified_diff(
            [line + "\n" for line in expected_lines], [line + "\n" for line in returned_lines],
            fromfile="expected", tofile="read-back"))
        report["expected_acl_format"] = inspect_acl(expected_acl)
        report["returned_acl_format"] = inspect_acl(returned_acl)
    if not other_matches:
        # Report field names only; unrelated attribute values may contain secrets.
        differences = []
        for index in range(max(len(expected_other), len(returned_other))):
            before = expected_other[index] if index < len(expected_other) else {}
            after = returned_other[index] if index < len(returned_other) else {}
            keys = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key)
                          or (key in before) != (key in after))
            if keys:
                differences.append({"position": index, "expected_name": before.get("name"),
                                    "returned_name": after.get("name"), "different_fields": keys})
        report["attribute_differences"] = differences
    return report


def inspect_acl(value):
    """Describe only the selected ACL, without dumping other profile attributes."""
    lines = value.splitlines(keepends=True)
    logical_lines = split_acl_lines(value)
    contexts = []
    for match in re.finditer(IP_PATTERN, value):
        try:
            address = ipaddress.IPv4Address(match[0])
        except ValueError:
            continue
        if any(address in network for network in RFC1918):
            continue
        contexts.append({"ip": str(address), "context_repr": repr(
            value[max(0, match.start() - 70):match.end() + 70])})
        if len(contexts) == 12:
            break
    return {
        "attribute_type": ATTRIBUTE_TYPE, "attribute_name": ATTRIBUTE_NAME,
        "characters": len(value), "physical_lines": len(lines), "logical_lines": len(logical_lines),
        "newline_characters": value.count("\n"), "carriage_return_characters": value.count("\r"),
        "literal_backslash_n": value.count(r"\n"), "literal_backslash_r": value.count(r"\r"),
        "html_breaks": len(re.findall(r"<br\s*/?>", value, re.I)),
        "matching_https_lines": sum(bool(RULE_PATTERN.fullmatch(line)) for line in logical_lines),
        "first_line_repr": repr(lines[0][:200]) if lines else "''",
        "non_rfc1918_ip_contexts": contexts,
    }


def cloud_block(acl):
    """Locate the only adjacent block of non-RFC1918 HTTPS host permits."""
    lines = split_acl_lines(acl)
    matches = []
    for index, line in enumerate(lines):
        match = RULE_PATTERN.fullmatch(line)
        if match:
            address = ipaddress.IPv4Address(match[2])
            if not any(address in network for network in RFC1918):
                matches.append((index, match))
    if not matches:
        raise UpdateError("No non-RFC1918 'permit tcp any host ... eq 443' rules found",
                          inspect_acl(acl))
    start, end = matches[0][0], matches[-1][0]
    if end - start + 1 != len(matches):
        raise UpdateError("Non-RFC1918 HTTPS rules are not one adjacent block; refusing to modify the ACL")
    return lines, start, end, matches


def resolve_ipv4(host):
    try:
        records = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UpdateError("DNS lookup failed for {}: {}".format(host, exc)) from exc
    addresses = sorted({str(ipaddress.IPv4Address(r[4][0])) for r in records},
                       key=ipaddress.IPv4Address)
    if not addresses:
        raise UpdateError("DNS returned no IPv4 addresses for " + host)
    # These printer-cloud hosts must resolve to public unicast destinations.
    if any(not ipaddress.IPv4Address(ip).is_global
           or ipaddress.IPv4Address(ip).is_multicast for ip in addresses):
        raise UpdateError("DNS returned a non-public IPv4 address for " + host)
    return addresses


def rewrite_acl(current, resolved):
    current = normalize_acl(current)
    lines, start, end, matches = cloud_block(current)
    addresses = sorted({ip for values in resolved.values() for ip in values}, key=ipaddress.IPv4Address)
    if not addresses:
        raise UpdateError("Refusing to replace the public ACL block with no addresses")
    # Preserve existing formatting and order when only the DNS answer order changes.
    if {m[2] for _, m in matches} == set(addresses) and len(matches) == len(addresses):
        return current
    first = matches[0][1]
    separator = first[4] or "\n"
    if not first[4] and start > 0:
        # A single managed rule at EOF has no terminator: use the preceding rule's separator.
        separator = ACL_SEPARATOR.search(lines[start - 1])[0]
    ending = matches[-1][1][4] or ""
    replacement = separator.join(first[1] + ip + first[3] for ip in addresses) + ending
    return "".join(lines[:start]) + replacement + "".join(lines[end + 1:])


def save_exclusive(path, content):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def update(client, profile_name, apply=False, backup=None, force=False):
    profile = client.profile(profile_name)
    index = acl_index(profile)
    current = profile["attributes"][index]["value"]
    cloud_block(current)
    resolved = {host: resolve_ipv4(host) for host in HOSTS}
    desired = rewrite_acl(current, resolved)
    # GET may render stored newlines as HTML. Compare logical content to avoid
    # writing on every scheduled run. --force repairs an earlier HTML-valued PATCH.
    pending = comparison_lines(desired) != comparison_lines(current) or force
    result = {"profile": profile_name, "resolved": resolved, "would_change": pending,
              "changed": False, "mode": "apply" if apply else "preview",
              "forced": force, "outgoing_line_breaks": "LF",
              "diff": "".join(difflib.unified_diff(
                  acl_diff_lines(current), acl_diff_lines(desired),
                  fromfile="current", tofile="DNS"))}
    if not pending or not apply:
        return result
    if not backup:
        raise UpdateError("--backup is required with --apply when changes are needed")
    path = "/api/enforcement-profile/" + str(profile["id"])
    fresh = client.request("GET", path)
    if fresh.get("name") != profile_name or fresh.get("attributes") != profile["attributes"]:
        raise UpdateError("Profile changed during this run; refusing to overwrite it")
    save_exclusive(backup, json.dumps(fresh, indent=2) + "\n")
    attributes = copy.deepcopy(profile["attributes"])
    attributes[index]["value"] = desired
    # This endpoint patches fields, not individual array elements. Preserve the complete array.
    client.request("PATCH", path, {"attributes": attributes})
    verification = verify_attributes(attributes, client.request("GET", path).get("attributes"))
    if not verification["matches"]:
        raise UpdateError("PATCH was sent but read-back verification differed; inspect verification_diagnostics before retrying",
                          verification, diagnostic_key="verification_diagnostics", write_attempted=True)
    result.update(changed=True, verified=True, backup=str(backup))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("CLEARPASS_URL"))
    parser.add_argument("--profile", default=PROFILE)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Write changes; default is preview only")
    mode.add_argument("--inspect", action="store_true", help="Read and describe the ACL's exact API formatting; no DNS lookup or PATCH")
    parser.add_argument("--force", action="store_true", help="Write even if DNS is unchanged; use once to repair previously stored HTML separators")
    parser.add_argument("--backup", type=Path, help="New file for full original profile; required for writes")
    parser.add_argument("--ca-file", default=os.environ.get("CLEARPASS_CA_FILE") or None)
    parser.add_argument("--insecure", action="store_true", help="Disable certificate verification for testing")
    args = parser.parse_args(argv)
    if not args.url:
        parser.error("Set CLEARPASS_URL or pass --url")
    try:
        client = ClearPass(args.url, args.ca_file, args.insecure)
        if args.inspect:
            profile = client.profile(args.profile)
            result = {"changed": False, "mode": "inspect", "profile": args.profile,
                      "acl_diagnostics": inspect_acl(profile["attributes"][acl_index(profile)]["value"])}
        else:
            result = update(client, args.profile, args.apply, args.backup, args.force)
        print(json.dumps(result))
        return 0
    except (UpdateError, OSError, ValueError) as exc:
        result = {"changed": False, "error": str(exc)}
        if isinstance(exc, UpdateError) and exc.diagnostics is not None:
            result[exc.diagnostic_key] = exc.diagnostics
        if isinstance(exc, UpdateError) and exc.write_attempted:
            result.update(changed=None, write_attempted=True, verified=False)
        print(json.dumps(result))
        return 1


if __name__ == "__main__":
    sys.exit(main())
