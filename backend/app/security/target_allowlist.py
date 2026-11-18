"""Fail-closed validation for controlled lab targets.

Every future component that makes a request to a target must call
``validate_controlled_target`` before opening a connection. The default policy
allows loopback only; private networks require explicit CIDR configuration.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


class TargetNotAllowed(ValueError):
    """Raised when a target is outside the configured controlled lab."""


@dataclass(frozen=True)
class TargetPolicy:
    allowed_hosts: frozenset[str]
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]

    @classmethod
    def from_strings(cls, hosts: str, cidrs: str) -> TargetPolicy:
        parsed_hosts = frozenset(
            item.strip().lower().rstrip(".") for item in hosts.split(",") if item.strip()
        )
        parsed_networks = tuple(
            ipaddress.ip_network(item.strip(), strict=False)
            for item in cidrs.split(",")
            if item.strip()
        )
        return cls(allowed_hosts=parsed_hosts, allowed_networks=parsed_networks)


def validate_controlled_target(target_url: str, policy: TargetPolicy) -> str:
    """Validate and return a normalized URL for a controlled target.

    This deliberately does not resolve arbitrary DNS names. Hostnames must be
    explicitly listed, while IP literals must fall inside an explicitly listed
    network. Credentials and non-HTTP schemes are rejected.
    """

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetNotAllowed("target must use http/https and include a hostname")
    if parsed.username or parsed.password:
        raise TargetNotAllowed("target URLs must not contain credentials")

    hostname = parsed.hostname.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if hostname not in policy.allowed_hosts:
            raise TargetNotAllowed("target hostname is not on the controlled allowlist") from None
    else:
        if not any(address in network for network in policy.allowed_networks):
            raise TargetNotAllowed("target address is not inside an allowed controlled network")

    return parsed.geturl()
