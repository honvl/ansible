#!/usr/bin/python
"""Resolve a complete controller-side IPv4 DNS snapshot for branch bypass."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: branch_bypass_dns
short_description: Resolve DNS names to controller-visible IPv4 addresses
description:
  - Resolves every supplied DNS name with the controller's system resolver.
  - Returns a deterministic mapping of names to unique IPv4 addresses.
  - Fails the complete snapshot if any name fails or has no IPv4 result.
options:
  domains:
    description:
      - Canonical DNS names to resolve.
    required: true
    type: list
    elements: str
  maximum_address_count:
    description:
      - Maximum total number of DNS answers accepted before deduplication across names.
    type: int
    default: 5000
author:
  - Branch bypass automation
"""


EXAMPLES = r"""
- name: Resolve application domains once on the controller
  branch_bypass_dns:
    domains:
      - api.example.com
      - media.example.com
  delegate_to: localhost
  run_once: true
"""


RETURN = r"""
answers:
  description: DNS-name-to-IPv4-address-list mapping.
  returned: always
  type: dict
domain_count:
  description: Number of DNS names resolved.
  returned: always
  type: int
address_count:
  description: Sum of unique IPv4 answers for all names.
  returned: always
  type: int
"""


import socket
from ipaddress import IPv4Address

from ansible.module_utils.basic import AnsibleModule


def resolve_domains(domains, maximum_address_count, resolver=None):
    """Return all IPv4 answers or raise ValueError without a partial result."""
    if resolver is None:
        resolver = socket.getaddrinfo

    answers = {}
    address_count = 0
    for domain in domains:
        try:
            records = resolver(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError("DNS lookup failed for {}: {}".format(domain, exc))

        addresses = set()
        for record in records:
            try:
                raw_address = record[4][0]
                address = IPv4Address(raw_address)
            except (IndexError, TypeError, ValueError) as exc:
                raise ValueError(
                    "DNS lookup returned an invalid IPv4 answer for {}: {}".format(
                        domain, exc
                    )
                )
            addresses.add(address)

        if not addresses:
            raise ValueError("DNS lookup returned no IPv4 addresses for {}".format(domain))

        ordered = sorted(addresses, key=int)
        address_count += len(ordered)
        if address_count > maximum_address_count:
            raise ValueError(
                "DNS answers exceed branch_bypass_maximum_prefix_count ({})".format(
                    maximum_address_count
                )
            )
        answers[domain] = [str(address) for address in ordered]

    return answers, address_count


def main():
    module = AnsibleModule(
        argument_spec={
            "domains": {"type": "list", "elements": "str", "required": True},
            "maximum_address_count": {"type": "int", "default": 5000},
        },
        supports_check_mode=True,
    )

    domains = module.params["domains"]
    maximum_address_count = module.params["maximum_address_count"]
    if maximum_address_count < 1:
        module.fail_json(msg="maximum_address_count must be at least 1")

    try:
        answers, address_count = resolve_domains(domains, maximum_address_count)
    except ValueError as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(
        changed=False,
        answers=answers,
        domain_count=len(domains),
        address_count=address_count,
    )


if __name__ == "__main__":
    main()
