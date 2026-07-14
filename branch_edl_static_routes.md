# Branch EDL static routes

[`branch_edl_static_routes.yml`](branch_edl_static_routes.yml) downloads external
IPv4 EDLs once on the Ansible controller and reconciles Cisco IOS/IOS XE static
routes toward each branch's local firewall. The built-in sources are Palo Alto
Networks' public [Zoom Meetings IPv4][zoom-meetings] and [Zoom Phone IPv4][zoom-phone]
feeds.

The playbook is generic: replace or extend `branch_bypass_sources` to handle other
line-oriented IPv4 feeds and custom application prefixes.

This playbook targets the `master` branch runtime: Ansible Tower 3.8.6,
Ansible 2.9.27, and Python 3.6. The collection requirements pin
`cisco.ios 5.3.0`—the newest release whose [compatibility metadata][cisco-compat]
supports Ansible 2.9—and its tested `ansible.netcommon 2.5.1` and
`ansible.utils 2.5.2` dependencies. Pin all three; otherwise Galaxy can resolve
new transitive dependencies that require a newer Ansible Core.

## Inventory

Keep the next hop host-scoped because it is different at every branch:

```yaml
all:
  children:
    switches:
      hosts:
        branch-router-01:
          ansible_host: 192.0.2.10
          ansible_network_os: cisco.ios.ios
          branch_bypass_firewall_next_hop: 10.10.10.1
        branch-router-02:
          ansible_host: 192.0.2.20
          ansible_network_os: cisco.ios.ios
          branch_bypass_firewall_next_hop: 10.20.20.1
```

The same variables can live in each router's `host_vars` file. Authentication and
privilege-escalation variables are intentionally omitted from this example.

The default target group is `switches`. Override it with, for example,
`-e target_hosts=branch_routers`.

## Add feeds or custom application prefixes

Define the source list as a common variable (for example, in `group_vars/all.yml`
or an extra-vars file). Every target in one playbook invocation must use the same
list.

```yaml
branch_bypass_sources:
  - name: zoom_meetings_ipv4
    url: https://saasedl.paloaltonetworks.com/feeds/zoom/zoom-meetings/ipv4
  - name: zoom_phone_ipv4
    url: https://saasedl.paloaltonetworks.com/feeds/zoom/zoom-phone/ipv4
  - name: vendor_edl
    url: https://vendor.example.net/application-ipv4.txt
  - name: custom_application
    prefixes:
      - 1.1.1.0/24
      - 8.8.4.4
```

Feeds are expected to contain one IPv4 CIDR (or single IPv4 address) per line.
Blank lines and `#` comments are ignored. All entries are validated, deduplicated,
and safely collapsed with Python's standard `ipaddress` library. A failed download,
empty feed, malformed entry, or validation error stops the run before any router is
changed.

Public prefixes are required by default. For a deliberately private custom
destination, set `branch_bypass_require_global_prefixes: false`. The broadest
accepted route defaults to `/8`, and the raw/collapsed input cap defaults to 5,000:

```yaml
branch_bypass_minimum_prefix_length: 8
branch_bypass_maximum_prefix_count: 5000
```

## Ownership and stale routes

Managed routes carry both of these markers by default:

```yaml
branch_bypass_route_name: ANS_BRANCH_BYPASS
branch_bypass_route_tag: 424242
```

A current static route is considered owned only when **both** markers match. The
playbook reads exact `ip route` configuration lines, uses
`cisco.ios.ios_static_routes` with `state: merged` to add only missing owned
routes, then re-reads and revalidates the configuration immediately before using
`cisco.ios.ios_config` to negate each full stale line. It never uses `replaced`,
`overridden`, destination-only deletion, or an empty deletion request. Unrelated
static routes are not removed.

The split is intentional even though `ios_static_routes` itself is compatible
with this Tower runtime. In 5.3.0, resource-module delete identity does not include
the route `name` or `tag`, and its gathered-route parser can combine same-base
prefixes with different masks. The latter was fixed only in [a later upstream
commit][cisco-static-fix] whose release line requires a newer Ansible Core. Exact
line parsing and deletion preserves the ownership boundary on Ansible 2.9 while
still using the supported resource module for additions.

As an additional safety boundary, the run fails before changes if it finds:

- only one of the two ownership markers on a route; or
- an unmanaged static route with exactly the same destination as a desired route.

Resolve an existing manual-route collision intentionally before the first rollout.
`branch_bypass_allow_destination_overlap: true` disables the second check, but can
create ECMP and should be used only when that is deliberate. It still refuses an
unmanaged route with the same destination **and** next hop, because merging that
record could adopt the manual route into this ownership domain.

Stale pruning is enabled so feed changes are reconciled. More than 100 stale owned
routes in one run trips a guardrail:

```yaml
branch_bypass_prune_stale_routes: true
branch_bypass_max_prune: 100
# Set only after reviewing an unusually large legitimate change:
branch_bypass_allow_large_prune: true
```

Keep the ownership name and tag stable. Changing either creates a new ownership
domain; the old marked routes will not be silently adopted or deleted.

## Run safely

Preview one branch first:

```bash
.venv/bin/ansible-playbook -i inventory branch_edl_static_routes.yml \
  --limit branch-router-01 --check --diff
```

Apply to that branch, then expand the limit after review:

```bash
.venv/bin/ansible-playbook -i inventory branch_edl_static_routes.yml \
  --limit branch-router-01
```

The playbook verifies the running route state after a change. It does not save the
running configuration by default because `write memory` also persists unrelated
pending changes. Enable saving only when that operational tradeoff is acceptable:

```yaml
branch_bypass_save_config: true
```

For a non-default routing table, set `branch_bypass_vrf` per branch or group. If
the controller needs a private CA chain, set `branch_bypass_ca_path`; otherwise the
playbook points `SSL_CERT_FILE` at Certifi when installed and falls back to the
controller's system trust. This mechanism is compatible with Ansible 2.9, whose
`uri` module does not yet have the newer `ca_path` parameter.

To validate only the controller-side downloads and parsing without logging in to
routers, run the `branch_bypass_resolve` tag against any inventory host that has
the required next-hop variable.

[zoom-meetings]: https://saasedl.paloaltonetworks.com/feeds/zoom/zoom-meetings/ipv4
[zoom-phone]: https://saasedl.paloaltonetworks.com/feeds/zoom/zoom-phone/ipv4
[cisco-compat]: https://github.com/ansible-collections/cisco.ios/blob/v5.3.0/README.md#ansible-version-compatibility
[cisco-static-fix]: https://github.com/ansible-collections/cisco.ios/commit/410718f4
