from __future__ import annotations

import pytest

from tests.probes import can_nested_net, can_nested_user, has_bwrap


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("integration") and not has_bwrap():
        pytest.skip("bwrap not available")
    if item.get_closest_marker("requires_nested_net") and not can_nested_net():
        pytest.skip("nested user+net namespace not available")
    if item.get_closest_marker("requires_nested_user") and not can_nested_user():
        pytest.skip("nested user namespace not available")
