from __future__ import annotations

from pathlib import Path

import pytest


pytestmark = pytest.mark.integration


def test_chdir_is_workdir(run_bk, integ_workspace: dict[str, Path]) -> None:
    work = integ_workspace["work"]
    proc = run_bk("--network", "none", "--", "/bin/pwd")
    assert proc.returncode == 0, proc.stderr
    assert Path(proc.stdout.strip()) == work


def test_nested_path_under_workdir_writable(
    run_bk, integ_workspace: dict[str, Path]
) -> None:
    nested = integ_workspace["work"] / "sub" / "deep" / "file.txt"
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"mkdir -p '{nested.parent}' && echo ok > '{nested}'",
    )
    assert proc.returncode == 0, proc.stderr
    assert nested.read_text(encoding="utf-8") == "ok\n"


def test_ro_config_bind_not_writable(
    run_bk, integ_workspace: dict[str, Path]
) -> None:
    ro_dir = integ_workspace["home"].parent / "ro-data"
    ro_dir.mkdir()
    marker = ro_dir / "marker.txt"
    marker.write_text("readable\n", encoding="utf-8")

    config = integ_workspace["config"]
    config.write_text(
        "features = []\n"
        "\n"
        "[[binds]]\n"
        f'source = "{integ_workspace["work"]}"\n'
        "read_only = false\n"
        "\n"
        "[[binds]]\n"
        f'source = "{ro_dir}"\n'
        "read_only = true\n",
        encoding="utf-8",
    )

    read_proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"cat '{marker}'",
    )
    assert read_proc.returncode == 0, read_proc.stderr
    assert read_proc.stdout == "readable\n"

    write_proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"echo no > '{marker}'",
    )
    assert write_proc.returncode != 0
    assert marker.read_text(encoding="utf-8") == "readable\n"


def test_dev_and_proc_present(run_bk) -> None:
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        "test -c /dev/null && test -d /proc/self && echo OK",
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_etc_passwd_readable_shadow_absent(run_bk) -> None:
    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        "test -r /etc/passwd && test ! -e /etc/shadow && echo OK",
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout


def test_tmp_is_private_tmpfs(run_bk, tmp_path: Path) -> None:
    host_marker = Path("/tmp") / f"buddelkiste-integ-{tmp_path.name}"
    try:
        if host_marker.exists():
            host_marker.unlink()
    except OSError:
        pytest.skip("cannot manage host /tmp marker")

    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"echo sandboxed > '{host_marker}' && test -f '{host_marker}' && echo OK",
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
    assert not host_marker.exists()


def test_symlink_to_unbound_host_path_does_not_leak(
    run_bk, integ_workspace: dict[str, Path], tmp_path: Path
) -> None:
    outside = tmp_path / "outside-secret"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("classified\n", encoding="utf-8")

    link = integ_workspace["work"] / "leak"
    link.symlink_to(secret)

    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        f"cat '{link}' 2>/dev/null || echo BLOCKED",
    )
    assert proc.returncode == 0, proc.stderr
    assert "classified" not in proc.stdout
    assert "BLOCKED" in proc.stdout


def test_custom_target_mount(
    run_bk, integ_workspace: dict[str, Path]
) -> None:
    src = integ_workspace["home"].parent / "alias-src"
    src.mkdir()
    (src / "payload.txt").write_text("via-target\n", encoding="utf-8")

    config = integ_workspace["config"]
    config.write_text(
        "features = []\n"
        "\n"
        "[[binds]]\n"
        f'source = "{integ_workspace["work"]}"\n'
        "read_only = false\n"
        "\n"
        "[[binds]]\n"
        f'source = "{src}"\n'
        'target = "/mnt/alias"\n'
        "read_only = true\n",
        encoding="utf-8",
    )

    proc = run_bk(
        "--network",
        "none",
        "--",
        "/bin/sh",
        "-c",
        "cat /mnt/alias/payload.txt",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "via-target\n"
