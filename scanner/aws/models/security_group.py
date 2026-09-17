from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityGroupRule:
    """
    Normalized inbound security-group permission.

    This model represents one inbound rule independently
    of the raw AWS API response.
    """

    protocol: str
    from_port: int | None
    to_port: int | None

    ipv4_cidr: str | None = None
    ipv6_cidr: str | None = None

    source_security_group_id: str | None = None

    @property
    def is_cidr_source(self) -> bool:
        return (
            self.ipv4_cidr is not None
            or self.ipv6_cidr is not None
        )

    @property
    def is_all_ipv4(self) -> bool:
        return self.ipv4_cidr == "0.0.0.0/0"

    @property
    def is_all_ipv6(self) -> bool:
        return self.ipv6_cidr == "::/0"
