from __future__ import annotations

import pytest

from tests.probes import (
    can_nested_net,
    has_bwrap,
    has_net_helper,
    has_nft,
    has_outbound_network,
    has_setpriv,
    has_tun,
)


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("requires_tun"):
        missing = []
        if not has_tun():
            missing.append("/dev/net/tun")
        if not has_bwrap():
            missing.append("bwrap")
        if not has_nft():
            missing.append("nft")
        if not has_setpriv():
            missing.append("setpriv")
        if not has_net_helper():
            missing.append("pasta|slirp4netns")
        if not can_nested_net():
            missing.append("unshare --user --net")
        if missing:
            pytest.skip("filter e2e unavailable (missing: " + ", ".join(missing) + ")")
    if item.get_closest_marker("requires_outbound") and not has_outbound_network():
        pytest.skip("no outbound network to 1.1.1.1:443")
