from typing import Any


HIGH_RISK_PORTS = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        110,
        135,
        143,
        445,
        1433,
        1434,
        3000,
        3306,
        3389,
        4333,
        5000,
        5432,
        5500,
        5601,
        8080,
        8088,
        8888,
        9200,
        9300,
    }
)

REMOTE_ADMIN_PORTS = frozenset({22, 3389})


def is_unrestricted_ipv4(rule: dict[str, Any]) -> bool:
    return any(
        item.get("CidrIp") == "0.0.0.0/0"
        for item in rule.get("IpRanges", [])
    )


def is_unrestricted_ipv6(rule: dict[str, Any]) -> bool:
    return any(
        item.get("CidrIpv6") == "::/0"
        for item in rule.get("Ipv6Ranges", [])
    )


def get_rule_ports(rule: dict[str, Any]) -> tuple[int, int] | None:
    protocol = str(rule.get("IpProtocol", "")).lower()

    if protocol in {"-1", "all"}:
        return None

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if from_port is None or to_port is None:
        return None

    try:
        return int(from_port), int(to_port)
    except (TypeError, ValueError):
        return None


def port_range_intersects(
    rule: dict[str, Any],
    ports: frozenset[int] | set[int],
) -> bool:
    protocol = str(rule.get("IpProtocol", "")).lower()

    if protocol in {"-1", "all"}:
        return True

    if protocol not in {"tcp", "6"}:
        return False

    port_range = get_rule_ports(rule)

    if port_range is None:
        return False

    start, end = port_range

    if start > end:
        start, end = end, start

    return any(start <= port <= end for port in ports)


def tcp_range_is_authorized(
    rule: dict[str, Any],
    authorized_ports: frozenset[int] | set[int],
) -> bool:
    protocol = str(rule.get("IpProtocol", "")).lower()

    if protocol in {"-1", "all"}:
        return False

    if protocol in {"udp", "17"}:
        # No default authorized UDP-port list exists in the
        # corresponding AWS control, so unrestricted UDP is
        # treated as unauthorized by this implementation.
        return False

    if protocol not in {"tcp", "6"}:
        return True

    port_range = get_rule_ports(rule)

    if port_range is None:
        return False

    start, end = port_range

    if start > end:
        start, end = end, start

    return all(
        port in authorized_ports
        for port in range(start, end + 1)
    )
