"""Filters for safely reconciling controller-managed Cisco static routes."""

from ipaddress import IPv4Address, IPv4Network, collapse_addresses, ip_address
import re

from ansible.errors import AnsibleFilterError


_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SAFE_VRF = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _fail(message):
    raise AnsibleFilterError(message)


def _source_name(source, index):
    if not isinstance(source, dict):
        _fail(f"branch_bypass_sources[{index}] must be a dictionary")

    name = source.get("name")
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name):
        _fail(
            f"branch_bypass_sources[{index}].name must contain only letters, "
            "numbers, dot, underscore, or hyphen"
        )
    return name


def branch_bypass_source_urls(sources):
    """Validate the source skeleton and return unique feed URLs in order."""
    if not isinstance(sources, list) or not sources:
        _fail("branch_bypass_sources must be a non-empty list")

    names = set()
    urls = []
    for index, source in enumerate(sources):
        name = _source_name(source, index)
        if name in names:
            _fail(f"duplicate branch bypass source name: {name}")
        names.add(name)

        url = source.get("url")
        prefixes = source.get("prefixes")
        if url is None and prefixes is None:
            _fail(f"source {name} must define url and/or prefixes")
        if url is not None:
            if not isinstance(url, str) or not url.startswith("https://"):
                _fail(f"source {name} url must be an https:// URL")
            if url not in urls:
                urls.append(url)
        if prefixes is not None and not isinstance(prefixes, list):
            _fail(f"source {name} prefixes must be a list")

    return urls


def branch_bypass_feed_contents(download_results):
    """Convert Ansible uri loop results into a URL-to-content dictionary."""
    if download_results is None:
        return {}
    if not isinstance(download_results, list):
        _fail("downloaded feed results must be a list")

    contents = {}
    for index, result in enumerate(download_results):
        if not isinstance(result, dict):
            _fail("downloaded feed result {} must be a dictionary".format(index))
        url = result.get("item")
        content = result.get("content")
        if not isinstance(url, str) or not isinstance(content, str):
            _fail("downloaded feed result {} is missing its URL or text content".format(index))
        contents[url] = content
    return contents


def _parse_prefix(
    value,
    source_name,
    location,
    minimum_prefix_length,
    require_global,
):
    if not isinstance(value, str):
        _fail(f"{source_name} {location} must be a string")

    token = value.strip()
    if not token:
        _fail(f"{source_name} {location} is empty")
    if "/" not in token:
        token = f"{token}/32"

    try:
        network = IPv4Network(token, strict=True)
    except ValueError as exc:
        _fail(f"{source_name} {location} is not a canonical IPv4 prefix: {value!r} ({exc})")

    if network.prefixlen < minimum_prefix_length:
        _fail(
            f"{source_name} {location} contains {network}, broader than the "
            f"allowed /{minimum_prefix_length}"
        )
    if network.is_multicast or network.is_unspecified:
        _fail(f"{source_name} {location} contains unusable network {network}")
    if require_global and not network.is_global:
        _fail(f"{source_name} {location} contains non-public network {network}")

    return network


def _feed_lines(content, source_name):
    if not isinstance(content, str):
        _fail(f"feed content for {source_name} is not text")

    values = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        value = raw_line.split("#", 1)[0].strip()
        if value:
            values.append((value, f"line {line_number}"))
    if not values:
        _fail(f"feed for {source_name} is empty")
    return values


def branch_bypass_resolve_prefixes(
    sources,
    feed_contents,
    minimum_prefix_length=8,
    maximum_prefix_count=5000,
    require_global=True,
):
    """Validate, combine, deduplicate, and collapse all configured IPv4 sources."""
    urls = branch_bypass_source_urls(sources)
    if not isinstance(feed_contents, dict):
        _fail("downloaded feed contents must be a URL-to-content dictionary")

    try:
        minimum_prefix_length = int(minimum_prefix_length)
        maximum_prefix_count = int(maximum_prefix_count)
    except (TypeError, ValueError):
        _fail("minimum prefix length and maximum prefix count must be integers")
    if minimum_prefix_length < 1 or minimum_prefix_length > 32:
        _fail("minimum prefix length must be between 1 and 32")
    if maximum_prefix_count < 1:
        _fail("maximum prefix count must be at least 1")
    require_global = bool(require_global)

    missing_urls = [url for url in urls if url not in feed_contents]
    if missing_urls:
        _fail(f"missing downloaded content for: {', '.join(missing_urls)}")

    parsed = []
    for index, source in enumerate(sources):
        name = _source_name(source, index)
        source_values = []

        url = source.get("url")
        if url is not None:
            source_values.extend(_feed_lines(feed_contents[url], name))

        configured_prefixes = source.get("prefixes")
        if configured_prefixes is not None:
            source_values.extend(
                (value, f"prefixes[{prefix_index}]")
                for prefix_index, value in enumerate(configured_prefixes)
            )

        if not source_values:
            _fail(f"source {name} did not provide any prefixes")

        for value, location in source_values:
            parsed.append(
                _parse_prefix(
                    value,
                    name,
                    location,
                    minimum_prefix_length,
                    require_global,
                )
            )
            if len(parsed) > maximum_prefix_count:
                _fail(
                    f"raw source data exceeds branch_bypass_maximum_prefix_count "
                    f"({maximum_prefix_count})"
                )

    collapsed = list(collapse_addresses(parsed))
    if not collapsed:
        _fail("the combined branch bypass prefix list is empty")
    if len(collapsed) > maximum_prefix_count:
        _fail(
            f"collapsed source data exceeds branch_bypass_maximum_prefix_count "
            f"({maximum_prefix_count})"
        )

    collapsed.sort(key=lambda network: (int(network.network_address), network.prefixlen))
    return [str(network) for network in collapsed]


def _normalized_vrf(value):
    if value in (None, "", "default", "global"):
        return None
    if not isinstance(value, str) or not _SAFE_VRF.fullmatch(value):
        _fail("branch_bypass_vrf contains unsupported characters")
    return value


def _normalized_next_hop(value):
    try:
        address = ip_address(value)
    except ValueError as exc:
        _fail(f"branch_bypass_firewall_next_hop is invalid: {exc}")
    if not isinstance(address, IPv4Address):
        _fail("branch_bypass_firewall_next_hop must be IPv4")
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    ):
        _fail(f"branch_bypass_firewall_next_hop is not usable: {address}")
    return str(address)


def _normalized_marker(route_name, route_tag):
    if not isinstance(route_name, str) or not _SAFE_NAME.fullmatch(route_name):
        _fail(
            "branch_bypass_route_name must contain only letters, numbers, dot, "
            "underscore, or hyphen"
        )
    try:
        route_tag = int(route_tag)
    except (TypeError, ValueError):
        _fail("branch_bypass_route_tag must be an integer")
    if route_tag < 1 or route_tag > 4294967295:
        _fail("branch_bypass_route_tag must be between 1 and 4294967295")
    return route_name, route_tag


def _canonical_dest(value):
    try:
        return str(IPv4Network(value, strict=False))
    except (TypeError, ValueError) as exc:
        _fail(f"Cisco returned an invalid IPv4 route destination {value!r}: {exc}")


def _tag_matches(value, expected):
    try:
        return int(value) == expected
    except (TypeError, ValueError):
        return False


def _route_key(vrf, dest, next_hop, name, tag):
    return (vrf or "", dest, next_hop, name, tag)


def _token_after(tokens, keyword):
    try:
        position = tokens.index(keyword)
    except ValueError:
        return None
    if position + 1 >= len(tokens):
        return None
    return tokens[position + 1]


def _parse_ios_route_line(raw_line):
    """Parse the identity fields while retaining the exact IOS config line."""
    line = raw_line.strip()
    tokens = line.split()
    record = {
        "line": line,
        "vrf": None,
        "dest": None,
        "next_hop": None,
        "name": _token_after(tokens, "name"),
        "tag": _token_after(tokens, "tag"),
        "parse_error": None,
    }

    if len(tokens) < 4 or tokens[0:2] != ["ip", "route"]:
        record["parse_error"] = "not an IPv4 static-route configuration line"
        return record

    position = 2
    if tokens[position] == "vrf":
        if position + 2 >= len(tokens):
            record["parse_error"] = "VRF route is missing its VRF or destination"
            return record
        record["vrf"] = tokens[position + 1]
        position += 2

    try:
        if "/" in tokens[position]:
            network = IPv4Network(tokens[position], strict=False)
            next_hop_position = position + 1
        else:
            network = IPv4Network(
                "{}/{}".format(tokens[position], tokens[position + 1]),
                strict=False,
            )
            next_hop_position = position + 2
    except (IndexError, ValueError) as exc:
        record["parse_error"] = "invalid destination: {}".format(exc)
        return record

    record["dest"] = str(network)
    option_keywords = {
        "dhcp",
        "global",
        "multicast",
        "name",
        "permanent",
        "tag",
        "track",
    }
    for token in tokens[next_hop_position:]:
        if token in option_keywords:
            break
        try:
            candidate = ip_address(token)
        except ValueError:
            continue
        if isinstance(candidate, IPv4Address):
            record["next_hop"] = str(candidate)
            break

    return record


def _desired_route_record(dest, next_hop, route_name, route_tag, vrf):
    network = IPv4Network(dest, strict=False)
    command = ["ip", "route"]
    if vrf is not None:
        command.extend(["vrf", vrf])
    command.extend(
        [
            str(network.network_address),
            str(network.netmask),
            next_hop,
            "tag",
            str(route_tag),
            "name",
            route_name,
        ]
    )
    canonical_dest = str(network)
    key = _route_key(vrf, canonical_dest, next_hop, route_name, route_tag)
    return {
        "command": " ".join(command),
        "vrf": vrf,
        "dest": canonical_dest,
        "next_hop": {
            "forward_router_address": next_hop,
            "name": route_name,
            "tag": route_tag,
        },
        "key": key,
    }


def _resource_config(records):
    """Group flattened route records into ios_static_routes config data."""
    tables = {}
    for record in records:
        table_key = record["vrf"] or ""
        route_key = (record["dest"], record.get("topology") or "")
        table = tables.setdefault(table_key, {})
        route = table.setdefault(route_key, [])
        if record["next_hop"] not in route:
            route.append(record["next_hop"])

    config = []
    for table_key in sorted(tables):
        routes = []
        for route_key in sorted(
            tables[table_key],
            key=lambda key: (
                int(IPv4Network(key[0]).network_address),
                IPv4Network(key[0]).prefixlen,
                key[1],
            ),
        ):
            dest, topology = route_key
            route = {
                "dest": dest,
                "next_hops": tables[table_key][route_key],
            }
            if topology:
                route["topology"] = topology
            routes.append(route)

        table = {
            "address_families": [
                {
                    "afi": "ipv4",
                    "routes": routes,
                }
            ]
        }
        if table_key:
            table["vrf"] = table_key
        config.append(table)
    return config


def branch_bypass_route_plan(
    running_config,
    prefixes,
    next_hop,
    route_name="ANS_BRANCH_BYPASS",
    route_tag=424242,
    vrf=None,
    allow_destination_overlap=False,
):
    """Plan additions and exact-line deletes without claiming unrelated routes."""
    route_name, route_tag = _normalized_marker(route_name, route_tag)
    next_hop = _normalized_next_hop(next_hop)
    vrf = _normalized_vrf(vrf)
    allow_destination_overlap = bool(allow_destination_overlap)

    if not isinstance(prefixes, list) or not prefixes:
        _fail("resolved branch bypass prefixes must be a non-empty list")
    canonical_prefixes = {_canonical_dest(prefix) for prefix in prefixes}
    canonical_prefixes = sorted(
        canonical_prefixes,
        key=lambda prefix: (
            int(IPv4Network(prefix).network_address),
            IPv4Network(prefix).prefixlen,
        ),
    )
    desired_records = [
        _desired_route_record(dest, next_hop, route_name, route_tag, vrf)
        for dest in canonical_prefixes
    ]
    desired_by_key = {record["key"]: record for record in desired_records}
    desired_keys = set(desired_by_key)
    desired_destinations = {(vrf or "", dest) for dest in canonical_prefixes}

    if running_config is None:
        running_config = ""
    if not isinstance(running_config, str):
        _fail("Cisco static-route running configuration must be text")

    owned_records = []
    owned_keys = set()
    collisions = []
    identities = {}

    for raw_line in running_config.splitlines():
        if not raw_line.strip():
            continue
        current = _parse_ios_route_line(raw_line)
        name_matches = current["name"] == route_name
        tag_matches = _tag_matches(current["tag"], route_tag)
        table_label = current["vrf"] or "global"
        display_dest = current["dest"] or "unknown destination"
        display_forwarder = current["next_hop"] or "unknown next hop"

        if current["dest"] is not None and current["next_hop"] is not None:
            identity = (
                current["vrf"] or "",
                current["dest"],
                current["next_hop"],
            )
            if identity in identities:
                collisions.append(
                    f"duplicate static-route identity on {table_label} "
                    f"{current['dest']} via {current['next_hop']}: "
                    f"{identities[identity]!r} and {current['line']!r}"
                )
            else:
                identities[identity] = current["line"]

        if name_matches != tag_matches:
            collisions.append(
                f"partial ownership marker on {table_label} {display_dest} via "
                f"{display_forwarder} (name={current['name']!r}, tag={current['tag']!r})"
            )
            continue

        if name_matches and tag_matches:
            if current["parse_error"] is not None or current["next_hop"] is None:
                collisions.append(
                    f"owned-looking route could not be parsed safely: {current['line']} "
                    f"({current['parse_error'] or 'missing IPv4 next hop'})"
                )
                continue
            current_vrf = _normalized_vrf(current["vrf"])
            key = _route_key(
                current_vrf,
                current["dest"],
                current["next_hop"],
                route_name,
                route_tag,
            )
            owned_keys.add(key)
            current["key"] = key
            owned_records.append(current)
            continue

        destination_is_desired = (
            current["vrf"] or "",
            current["dest"],
        ) in desired_destinations
        exact_forwarder_overlap = (
            destination_is_desired and current["next_hop"] == next_hop
        )
        if destination_is_desired and (
            exact_forwarder_overlap or not allow_destination_overlap
        ):
            reason = (
                "same destination and next hop"
                if exact_forwarder_overlap
                else "same destination"
            )
            collisions.append(
                f"unmanaged static route uses the {reason}: {table_label} "
                f"{current['dest']} via {display_forwarder}"
            )

    stale_records = [record for record in owned_records if record["key"] not in desired_keys]
    missing_keys = sorted(desired_keys - owned_keys)
    missing_records = [desired_by_key[key] for key in missing_keys]
    delete_commands = sorted({"no " + record["line"] for record in stale_records})

    def describe(key):
        key_vrf, dest, forwarder, _name, _tag = key
        return f"{key_vrf or 'global'} {dest} via {forwarder}"

    return {
        "add_commands": [record["command"] for record in missing_records],
        "delete_commands": delete_commands,
        "missing_config": _resource_config(missing_records),
        "desired_count": len(desired_keys),
        "current_owned_count": len(owned_keys),
        "missing_count": len(missing_keys),
        "stale_count": len(delete_commands),
        "missing_routes": [describe(key) for key in missing_keys],
        "stale_routes": [record["line"] for record in stale_records],
        "collisions": sorted(set(collisions)),
    }


class FilterModule:
    """Expose filters to Ansible."""

    def filters(self):
        return {
            "branch_bypass_source_urls": branch_bypass_source_urls,
            "branch_bypass_feed_contents": branch_bypass_feed_contents,
            "branch_bypass_resolve_prefixes": branch_bypass_resolve_prefixes,
            "branch_bypass_route_plan": branch_bypass_route_plan,
        }
