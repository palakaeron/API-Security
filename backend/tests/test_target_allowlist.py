import ipaddress

import pytest
from app.security.target_allowlist import (
    TargetNotAllowed,
    TargetPolicy,
    validate_controlled_target,
)


@pytest.fixture
def loopback_policy() -> TargetPolicy:
    return TargetPolicy.from_strings("localhost,lab-api", "127.0.0.0/8,::1/128")


def test_allows_explicit_loopback_host(loopback_policy: TargetPolicy) -> None:
    assert validate_controlled_target("http://localhost:8080/users", loopback_policy) == (
        "http://localhost:8080/users"
    )


def test_allows_explicit_private_network_when_configured() -> None:
    policy = TargetPolicy.from_strings("", "10.0.0.0/8")

    assert validate_controlled_target("http://10.20.0.4:8080", policy).startswith(
        "http://10.20.0.4"
    )


def test_rejects_public_target(loopback_policy: TargetPolicy) -> None:
    with pytest.raises(TargetNotAllowed):
        validate_controlled_target("https://example.com", loopback_policy)


def test_rejects_embedded_credentials(loopback_policy: TargetPolicy) -> None:
    with pytest.raises(TargetNotAllowed):
        validate_controlled_target("http://user:password@localhost:8080", loopback_policy)


def test_policy_networks_are_ip_networks() -> None:
    policy = TargetPolicy.from_strings("localhost", "127.0.0.0/8")

    assert policy.allowed_networks == (ipaddress.ip_network("127.0.0.0/8"),)
