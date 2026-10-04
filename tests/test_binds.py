from __future__ import annotations

from pathlib import Path

import pytest

from buddelkiste.cli import (
    DevBindConfig,
    ROBindConfig,
    RWBindConfig,
    Tmpfs,
    get_bind_args,
    get_binds,
)
from buddelkiste.features import FEATURE_NAMES, base_binds, feature_binds


def test_ro_bind_iterates_when_source_exists(tmp_path: Path) -> None:
    src = tmp_path / "ro"
    src.mkdir()
    assert list(ROBindConfig(src)) == ["--ro-bind", str(src), str(src)]


def test_ro_bind_skips_missing_source(tmp_path: Path) -> None:
    assert list(ROBindConfig(tmp_path / "missing")) == []


def test_ro_bind_custom_target(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    target = "/mnt/src"
    assert list(ROBindConfig(src, target)) == ["--ro-bind", str(src), target]


def test_rw_bind_creates_missing_source(tmp_path: Path) -> None:
    src = tmp_path / "nested" / "rw"
    bind = RWBindConfig(src)
    assert src.is_dir()
    assert list(bind) == ["--bind", str(src), str(src)]


def test_dev_bind_and_tmpfs() -> None:
    assert list(DevBindConfig("/dev/null")) == ["--dev-bind", "/dev/null", "/dev/null"]
    assert list(Tmpfs("/tmp")) == ["--tmpfs", "/tmp"]


def test_basic_bind_requires_flag(tmp_path: Path) -> None:
    from buddelkiste.cli import BasicBindConfig

    src = tmp_path / "x"
    src.mkdir()
    with pytest.raises(TypeError, match="requires a bind flag"):
        list(BasicBindConfig(src))


@pytest.mark.parametrize(
    ("child", "covered"),
    [
        ("sub", True),
        ("sub/dir", True),
        (".", True),
    ],
)
def test_covers_path_for_descendants(
    tmp_path: Path, child: str, covered: bool
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    path = (root / child).resolve() if child != "." else root.resolve()
    if child != ".":
        path.mkdir(parents=True)
    assert ROBindConfig(root).covers_path(path) is covered


def test_covers_path_false_for_sibling(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert ROBindConfig(a).covers_path(b) is False


def test_covers_path_false_when_source_missing(tmp_path: Path) -> None:
    assert ROBindConfig(tmp_path / "missing").covers_path(tmp_path) is False


def test_get_bind_args_flattens(tmp_path: Path) -> None:
    src = tmp_path / "d"
    src.mkdir()
    args = get_bind_args([ROBindConfig(src), Tmpfs("/run"), ("--dir", "/run/dbus")])
    assert args == [
        "--ro-bind",
        str(src),
        str(src),
        "--tmpfs",
        "/run",
        "--dir",
        "/run/dbus",
    ]


def test_get_binds_appends_config_binds(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()

    extra = tmp_path / "extra"
    extra.mkdir()
    enabled = {name: False for name in FEATURE_NAMES}
    binds = get_binds(
        {
            "binds": [
                {"source": str(extra), "read_only": True},
                {"source": str(extra), "read_only": False},
            ]
        },
        enabled,
    )
    assert isinstance(binds[-2], ROBindConfig)
    assert isinstance(binds[-1], RWBindConfig)
    assert binds[-2].source == str(extra)


def test_get_binds_missing_source_raises(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    with pytest.raises(FileNotFoundError):
        get_binds({"binds": [{"source": str(tmp_path / "nope")}]}, {})


def test_covers_path_parent_of_source(tmp_path: Path) -> None:
    # Current semantics: a bind of a child also "covers" ancestor paths.
    child = tmp_path / "root" / "child"
    child.mkdir(parents=True)
    assert ROBindConfig(child).covers_path(tmp_path / "root") is True


def test_covers_path_resolves_symlinks(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    nested = real / "nested"
    nested.mkdir()
    assert ROBindConfig(link).covers_path(nested) is True


def test_covers_path_uses_source_not_target(tmp_path: Path) -> None:
    src = tmp_path / "src"
    cwd = tmp_path / "cwd"
    src.mkdir()
    cwd.mkdir()
    assert ROBindConfig(src, target=str(cwd)).covers_path(cwd) is False


def test_dev_bind_skips_missing_source(tmp_path: Path) -> None:
    assert list(DevBindConfig(tmp_path / "missing-dev")) == []


def test_get_binds_defaults_read_only_true(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    extra = tmp_path / "extra"
    extra.mkdir()
    binds = get_binds({"binds": [{"source": str(extra)}]}, {n: False for n in FEATURE_NAMES})
    assert isinstance(binds[-1], ROBindConfig)


def test_get_binds_passes_custom_target(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    extra = tmp_path / "extra"
    extra.mkdir()
    binds = get_binds(
        {"binds": [{"source": str(extra), "target": "/mnt/extra", "read_only": True}]},
        {n: False for n in FEATURE_NAMES},
    )
    assert list(binds[-1]) == ["--ro-bind", str(extra), "/mnt/extra"]


def test_get_bind_args_skips_missing_ro(tmp_path: Path) -> None:
    present = tmp_path / "present"
    present.mkdir()
    args = get_bind_args([ROBindConfig(present), ROBindConfig(tmp_path / "missing")])
    assert args == ["--ro-bind", str(present), str(present)]


def test_base_binds_include_dev_proc_tmpfs_and_omit_shadow(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    binds = base_binds()
    flat = get_bind_args(binds)
    assert flat[:2] == ["--dev", "/dev"]
    assert "--proc" in flat and flat[flat.index("--proc") + 1] == "/proc"
    assert ("--tmpfs", "/tmp") in [(flat[i], flat[i + 1]) for i in range(0, len(flat) - 1)]
    assert ("--tmpfs", "/run") in [(flat[i], flat[i + 1]) for i in range(0, len(flat) - 1)]
    assert "/etc/shadow" not in flat


def test_feature_binds_omit_ssh_when_disabled(
    tmp_path: Path, runtime_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    ssh_config = home / ".ssh" / "config"
    ssh_config.parent.mkdir()
    ssh_config.write_text("Host *\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    enabled = {name: False for name in FEATURE_NAMES}
    flat = get_bind_args(feature_binds(enabled))
    assert str(ssh_config) not in flat

    enabled["ssh"] = True
    flat_ssh = get_bind_args(feature_binds(enabled))
    assert str(ssh_config) in flat_ssh
