from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

from buddelkiste.network import NetworkConfig, build_nft_ruleset
from tests.probes import can_nested_nft

pytestmark = pytest.mark.integration


@pytest.mark.requires_nested_net
def test_apply_nft_ruleset_in_nested_netns() -> None:
    if not can_nested_nft():
        pytest.skip("nft in nested netns not available")

    rules = build_nft_ruleset(
        NetworkConfig(
            mode="filter",
            policy="deny",
            allow=["1.1.1.1/32", "2001:db8::1/128"],
            deny=["10.0.0.0/8"],
        ),
        dns_proxy=True,
    )
    script = textwrap.dedent(
        f"""
        import subprocess
        import sys

        rules = {rules!r}
        apply = subprocess.run(
            ["nft", "-f", "-"],
            input=rules,
            text=True,
            capture_output=True,
        )
        if apply.returncode != 0:
            sys.stderr.write(apply.stderr)
            sys.exit(apply.returncode)
        listed = subprocess.check_output(["nft", "list", "ruleset"], text=True)
        for needle in ("table inet buddelkiste", "1.1.1.1", "10.0.0.0/8", "dyn_allow4", "dns_redirect"):
            if needle not in listed:
                raise SystemExit(f"missing {{needle!r}} in:\\n{{listed}}")
        """
    )
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--net", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.requires_nested_user
def test_setpriv_can_drop_net_admin_in_nested_userns() -> None:
    script = textwrap.dedent(
        """
        import subprocess
        import sys

        before = open("/proc/self/status", encoding="utf-8").read()
        if "CapEff:\\t0000000000000000" in before:
            raise SystemExit("expected capabilities in nested userns")
        proc = subprocess.run(
            [
                "setpriv",
                "--bounding-set=-net_admin",
                "--inh-caps=-net_admin",
                "--ambient-caps=-net_admin",
                "--",
                "grep",
                "^CapEff:",
                "/proc/self/status",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            sys.exit(proc.returncode)
        # CAP_NET_ADMIN is bit 12 → mask clears 0x1000
        cap = int(proc.stdout.split()[1], 16)
        if cap & 0x1000:
            raise SystemExit(f"CAP_NET_ADMIN still present: {cap:#x}")
        """
    )
    proc = subprocess.run(
        ["unshare", "--user", "--map-root-user", "--", sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
