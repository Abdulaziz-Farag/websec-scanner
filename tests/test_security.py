import pytest

from app.security import UnsafeTarget, assert_public_host, normalize_target


def test_normalize_adds_scheme_and_strips_path():
    assert normalize_target("Example.com/path?x=1") == "https://example.com"


@pytest.mark.parametrize("bad", ["ftp://example.com", "https://user:pw@example.com", "http://", ""])
def test_normalize_rejects_bad_input(bad):
    with pytest.raises(UnsafeTarget):
        normalize_target(bad)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"])
def test_private_addresses_are_blocked(ip):
    with pytest.raises(UnsafeTarget):
        assert_public_host(ip)


def test_public_address_is_allowed():
    assert_public_host("8.8.8.8")
