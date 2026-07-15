"""Unit tests for the branch bypass Ansible filters."""

import importlib.util
from pathlib import Path
import unittest

from ansible.errors import AnsibleFilterError


PLUGIN_PATH = Path(__file__).parents[1] / "filter_plugins" / "branch_bypass.py"
SPEC = importlib.util.spec_from_file_location("branch_bypass", PLUGIN_PATH)
assert SPEC is not None and SPEC.loader is not None
PLUGIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLUGIN)

DNS_MODULE_PATH = Path(__file__).parents[1] / "library" / "branch_bypass_dns.py"
DNS_SPEC = importlib.util.spec_from_file_location("branch_bypass_dns", DNS_MODULE_PATH)
assert DNS_SPEC is not None and DNS_SPEC.loader is not None
DNS_MODULE = importlib.util.module_from_spec(DNS_SPEC)
DNS_SPEC.loader.exec_module(DNS_MODULE)


class SourceResolutionTests(unittest.TestCase):
    def test_collects_canonical_unique_domains(self):
        sources = [
            {
                "name": "application",
                "domains": [
                    "API.Example.COM.",
                    "api.example.com",
                    "media.example.com",
                ],
            }
        ]

        self.assertEqual(
            PLUGIN.branch_bypass_source_domains(sources),
            ["api.example.com", "media.example.com"],
        )

    def test_rejects_unsafe_or_non_fully_qualified_domains(self):
        invalid_domains = [
            "*.example.com",
            "https://api.example.com",
            "8.8.8.8",
            "8.8.8",
            "singlelabel",
            "bad_name.example.com",
            "api.example.com/path",
        ]
        for value in invalid_domains:
            with self.subTest(value=value):
                with self.assertRaises(AnsibleFilterError):
                    PLUGIN.branch_bypass_source_domains(
                        [{"name": "invalid", "domains": [value]}]
                    )

    def test_rejects_empty_or_non_list_domains(self):
        with self.assertRaisesRegex(AnsibleFilterError, "non-empty list"):
            PLUGIN.branch_bypass_source_domains(
                [{"name": "empty", "domains": []}]
            )
        with self.assertRaisesRegex(AnsibleFilterError, "non-empty list"):
            PLUGIN.branch_bypass_source_domains(
                [{"name": "string", "domains": "api.example.com"}]
            )

    def test_dns_module_deduplicates_and_numerically_sorts_ipv4_answers(self):
        def resolver(domain, service, family, socket_type):
            self.assertEqual(domain, "api.example.com")
            self.assertIsNone(service)
            self.assertEqual(family, DNS_MODULE.socket.AF_INET)
            self.assertEqual(socket_type, DNS_MODULE.socket.SOCK_STREAM)
            return [
                (family, socket_type, 6, "", ("9.9.9.9", 0)),
                (family, socket_type, 6, "", ("1.1.1.1", 0)),
                (family, socket_type, 6, "", ("9.9.9.9", 0)),
                (family, socket_type, 6, "", ("8.8.8.8", 0)),
            ]

        answers, address_count = DNS_MODULE.resolve_domains(
            ["api.example.com"], 10, resolver=resolver
        )

        self.assertEqual(
            answers,
            {"api.example.com": ["1.1.1.1", "8.8.8.8", "9.9.9.9"]},
        )
        self.assertEqual(address_count, 3)

    def test_dns_module_fails_the_snapshot_on_lookup_or_empty_answer(self):
        def failed_resolver(_domain, _service, _family, _socket_type):
            raise DNS_MODULE.socket.gaierror(-2, "name not known")

        with self.assertRaisesRegex(ValueError, "DNS lookup failed for missing.example"):
            DNS_MODULE.resolve_domains(
                ["missing.example"], 10, resolver=failed_resolver
            )

        with self.assertRaisesRegex(ValueError, "no IPv4 addresses"):
            DNS_MODULE.resolve_domains(
                ["empty.example"],
                10,
                resolver=lambda _domain, _service, _family, _socket_type: [],
            )

    def test_dns_module_enforces_answer_count_limit(self):
        records = [
            (DNS_MODULE.socket.AF_INET, DNS_MODULE.socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
            (DNS_MODULE.socket.AF_INET, DNS_MODULE.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        ]
        with self.assertRaisesRegex(ValueError, "maximum_prefix_count"):
            DNS_MODULE.resolve_domains(
                ["api.example.com"],
                1,
                resolver=lambda _domain, _service, _family, _socket_type: records,
            )

    def test_indexes_uri_results_without_losing_loop_entries(self):
        results = [
            {"item": "https://example.test/a", "content": "1.1.1.0/24\n"},
            {"item": "https://example.test/b", "content": "8.8.8.0/24\n"},
        ]
        self.assertEqual(
            PLUGIN.branch_bypass_feed_contents(results),
            {
                "https://example.test/a": "1.1.1.0/24\n",
                "https://example.test/b": "8.8.8.0/24\n",
            },
        )

    def test_combines_deduplicates_and_collapses_sources(self):
        sources = [
            {"name": "meetings", "url": "https://example.test/meetings"},
            {"name": "phone", "url": "https://example.test/phone"},
            {"name": "custom", "prefixes": ["9.9.9.9", "8.8.4.0/24"]},
        ]
        contents = {
            "https://example.test/meetings": "8.8.8.0/23\n1.1.1.0/24\n",
            "https://example.test/phone": "8.8.8.0/24 # covered\n1.1.1.0/24\n",
        }

        resolved = PLUGIN.branch_bypass_resolve_prefixes(sources, contents)

        self.assertEqual(
            resolved,
            ["1.1.1.0/24", "8.8.4.0/24", "8.8.8.0/23", "9.9.9.9/32"],
        )

    def test_combines_domain_answers_with_feeds_and_prefixes(self):
        sources = [
            {
                "name": "mixed",
                "url": "https://example.test/feed",
                "prefixes": ["9.9.9.9"],
                "domains": ["API.Example.COM."],
            }
        ]
        resolved = PLUGIN.branch_bypass_resolve_prefixes(
            sources,
            {"https://example.test/feed": "1.1.1.0/24\n"},
            domain_addresses={
                "api.example.com": ["8.8.8.8", "8.8.4.4", "8.8.8.8"]
            },
        )

        self.assertEqual(
            resolved,
            ["1.1.1.0/24", "8.8.4.4/32", "8.8.8.8/32", "9.9.9.9/32"],
        )

    def test_rejects_missing_empty_or_private_domain_answers(self):
        sources = [{"name": "application", "domains": ["api.example.com"]}]

        with self.assertRaisesRegex(AnsibleFilterError, "missing DNS answers"):
            PLUGIN.branch_bypass_resolve_prefixes(sources, {})
        with self.assertRaisesRegex(AnsibleFilterError, "non-empty IPv4 address list"):
            PLUGIN.branch_bypass_resolve_prefixes(
                sources, {}, domain_addresses={"api.example.com": []}
            )
        with self.assertRaisesRegex(AnsibleFilterError, "non-public"):
            PLUGIN.branch_bypass_resolve_prefixes(
                sources, {}, domain_addresses={"api.example.com": ["10.0.0.10"]}
            )

        self.assertEqual(
            PLUGIN.branch_bypass_resolve_prefixes(
                sources,
                {},
                domain_addresses={"api.example.com": ["10.0.0.10"]},
                require_global=False,
            ),
            ["10.0.0.10/32"],
        )

    def test_domain_answers_count_toward_the_raw_prefix_limit(self):
        sources = [{"name": "application", "domains": ["api.example.com"]}]
        with self.assertRaisesRegex(AnsibleFilterError, "maximum_prefix_count"):
            PLUGIN.branch_bypass_resolve_prefixes(
                sources,
                {},
                domain_addresses={
                    "api.example.com": ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
                },
                maximum_prefix_count=2,
            )

    def test_rejects_empty_feed(self):
        sources = [{"name": "empty", "url": "https://example.test/empty"}]
        with self.assertRaisesRegex(AnsibleFilterError, "feed for empty is empty"):
            PLUGIN.branch_bypass_resolve_prefixes(
                sources, {"https://example.test/empty": "# no entries\n"}
            )

    def test_rejects_malformed_or_noncanonical_prefix(self):
        sources = [{"name": "bad", "prefixes": ["8.8.8.1/24"]}]
        with self.assertRaisesRegex(AnsibleFilterError, "not a canonical IPv4 prefix"):
            PLUGIN.branch_bypass_resolve_prefixes(sources, {})

    def test_rejects_private_prefix_by_default(self):
        sources = [{"name": "private", "prefixes": ["10.0.0.0/8"]}]
        with self.assertRaisesRegex(AnsibleFilterError, "non-public"):
            PLUGIN.branch_bypass_resolve_prefixes(sources, {})

        self.assertEqual(
            PLUGIN.branch_bypass_resolve_prefixes(
                sources, {}, require_global=False
            ),
            ["10.0.0.0/8"],
        )


class RoutePlanTests(unittest.TestCase):
    marker = "ANS_BRANCH_BYPASS"
    tag = 424242

    def test_plan_keeps_owned_routes_and_deletes_only_exact_stale_routes(self):
        running_config = "\n".join(
            [
                "ip route 8.8.8.0 255.255.255.0 10.0.0.1 tag 424242 "
                "name ANS_BRANCH_BYPASS",
                "ip route 9.9.9.0 255.255.255.0 10.0.0.254 50 tag 424242 "
                "name ANS_BRANCH_BYPASS",
                "ip route 192.0.2.0 255.255.255.0 10.0.0.2 name MANUAL",
            ]
        )

        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.8.0/24", "1.1.1.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
        )

        self.assertEqual(plan["desired_count"], 2)
        self.assertEqual(plan["current_owned_count"], 2)
        self.assertEqual(plan["missing_count"], 1)
        self.assertEqual(plan["stale_count"], 1)
        self.assertEqual(plan["collisions"], [])
        self.assertEqual(
            plan["missing_config"],
            [
                {
                    "address_families": [
                        {
                            "afi": "ipv4",
                            "routes": [
                                {
                                    "dest": "1.1.1.0/24",
                                    "next_hops": [
                                        {
                                            "forward_router_address": "10.0.0.1",
                                            "name": "ANS_BRANCH_BYPASS",
                                            "tag": 424242,
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ],
        )
        self.assertEqual(
            plan["delete_commands"],
            [
                "no ip route 9.9.9.0 255.255.255.0 10.0.0.254 50 tag 424242 "
                "name ANS_BRANCH_BYPASS"
            ],
        )
        self.assertNotIn("192.0.2.0/24", str(plan["delete_commands"]))

    def test_plan_refuses_partial_marker(self):
        running_config = (
            "ip route 8.8.8.0 255.255.255.0 10.0.0.1 tag 99 "
            "name ANS_BRANCH_BYPASS"
        )

        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.8.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
        )

        self.assertEqual(len(plan["collisions"]), 1)
        self.assertIn("partial ownership marker", plan["collisions"][0])

    def test_plan_refuses_unmanaged_exact_destination(self):
        running_config = (
            "ip route 8.8.8.0 255.255.255.0 10.0.0.2 tag 7 name MANUAL"
        )

        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.8.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
        )
        self.assertIn("unmanaged static route", plan["collisions"][0])

        allowed = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.8.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
            allow_destination_overlap=True,
        )
        self.assertEqual(allowed["collisions"], [])

    def test_plan_never_adopts_unmanaged_route_with_same_next_hop(self):
        running_config = "ip route 8.8.8.0 255.255.255.0 10.0.0.1"
        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.8.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
            allow_destination_overlap=True,
        )
        self.assertIn("same destination and next hop", plan["collisions"][0])

    def test_plan_renders_vrf_route_in_ios_order(self):
        plan = PLUGIN.branch_bypass_route_plan(
            "",
            prefixes=["8.8.8.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
            vrf="INTERNET",
        )
        self.assertEqual(
            plan["missing_config"],
            [
                {
                    "vrf": "INTERNET",
                    "address_families": [
                        {
                            "afi": "ipv4",
                            "routes": [
                                {
                                    "dest": "8.8.8.0/24",
                                    "next_hops": [
                                        {
                                            "forward_router_address": "10.0.0.1",
                                            "name": "ANS_BRANCH_BYPASS",
                                            "tag": 424242,
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        )

    def test_plan_refuses_owned_route_without_ipv4_next_hop(self):
        running_config = (
            "ip route 8.8.8.0 255.255.255.0 Null0 tag 424242 "
            "name ANS_BRANCH_BYPASS"
        )
        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.8.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
        )
        self.assertIn("could not be parsed safely", plan["collisions"][0])

    def test_plan_refuses_duplicate_destination_and_next_hop_identity(self):
        running_config = "\n".join(
            [
                "ip route 8.8.8.0 255.255.255.0 10.0.0.1 10 name MANUAL_A",
                "ip route 8.8.8.0 255.255.255.0 10.0.0.1 20 name MANUAL_B",
            ]
        )
        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["1.1.1.0/24"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
        )
        self.assertIn("duplicate static-route identity", plan["collisions"][0])

    def test_plan_rejects_unusable_firewall_next_hop(self):
        with self.assertRaisesRegex(AnsibleFilterError, "not usable"):
            PLUGIN.branch_bypass_route_plan(
                "",
                prefixes=["1.1.1.0/24"],
                next_hop="169.254.1.1",
                route_name=self.marker,
                route_tag=self.tag,
            )

    def test_changed_dns_answer_prunes_only_the_old_owned_host_route(self):
        running_config = "\n".join(
            [
                "ip route 8.8.8.8 255.255.255.255 10.0.0.1 tag 424242 "
                "name ANS_BRANCH_BYPASS",
                "ip route 192.0.2.0 255.255.255.0 10.0.0.2 name MANUAL",
            ]
        )

        plan = PLUGIN.branch_bypass_route_plan(
            running_config,
            prefixes=["8.8.4.4/32"],
            next_hop="10.0.0.1",
            route_name=self.marker,
            route_tag=self.tag,
        )

        self.assertEqual(plan["missing_count"], 1)
        self.assertEqual(plan["stale_count"], 1)
        self.assertEqual(
            plan["delete_commands"],
            [
                "no ip route 8.8.8.8 255.255.255.255 10.0.0.1 tag 424242 "
                "name ANS_BRANCH_BYPASS"
            ],
        )
        self.assertNotIn("MANUAL", str(plan["delete_commands"]))


if __name__ == "__main__":
    unittest.main()
