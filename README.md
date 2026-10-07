# buddelkiste

Run a command in a rootless sandbox (`bk`): filesystem and process isolation
via [bubblewrap](https://github.com/containers/bubblewrap), plus optional
network controls — share the host stack, cut connectivity entirely, or filter
egress with pasta/slirp4netns and in-namespace nftables (IP/CIDR and hostname
rules, no root required).

## Usage

```bash
# Run a command in the sandbox
bk run /path/to/executable [args...]

# Inspect the sandbox (login shell)
bk run

# Catalog helpers
bk list-features
bk list-net-presets

# Host-side docker-proxy policy (outside the sandbox)
bk docker-policy show
bk docker-policy pending
bk docker-policy approve   # or: deny [id|image]

# PATH shims for configured [executables.*] (in ~/.local/bin)
bk shims install
bk shims check

# Topic features (only ``home`` on by default)
bk run --feature python --feature ssh python myscript.py
bk run --feature cursor --feature gui cursor-agent

# Network modes (filter is the default; denies internal + localhost)
bk run --network host …                 # share host network
bk run --network none …                 # no connectivity
bk run --network filter \
  --net-policy deny \
  --net-allow 1.1.1.1/32 \
  --net-allow api.github.com \
  --net-allow '*.pypi.org' \
  --net-deny-preset metadata …
```

`bk run` wrapper options: `--debug`, `--feature` / `--no-feature`,
`--network`, `--net-policy`, `--net-allow`, `--net-deny`, `--net-deny-preset`.
Everything else is the sandboxed command.

## Features

Optional permission sets are grouped by topic. Only **`home`** is enabled by
default; every other built-in is opt-in. Toggle with CLI flags or config; see
`bk list-features` for the live catalog (including each feature's module path).

| Feature | What it grants |
|---------|----------------|
| `asdf` | `~/.asdf`, `~/.tool-versions`, `ASDF_DIR` |
| `cursor` | Cursor IDE/CLI install and state dirs |
| `dbus` | session/system bus sockets, `DBUS_SESSION_BUS_ADDRESS` |
| `docker` | `~/.docker`, Docker socket / `DOCKER_HOST` (conflicts with `docker-proxy` / `docker-instance`) |
| `docker-proxy` | Filtered Docker API proxy + image allowlist (conflicts with `docker` / `docker-instance`) |
| `docker-instance` | Project-local rootless dockerd + FS/net isolation (conflicts with `docker` / `docker-proxy`) |
| `git` | `~/.gitconfig`, `~/.config/git` |
| `google` | `/opt/google` |
| `gui` | display, GPU, audio, fonts, related env |
| `home` | `~/.local` (ro), `~/.cache` (rw) — **default on** |
| `java` | OpenJDK `/etc/java-*-openjdk` configs |
| `locale` | `LANG`, `LC_NUMERIC`, `LC_TIME` |
| `node` | npm/nvm/bun paths, `BUN_INSTALL` |
| `nvim` | `~/nvim` |
| `python` | pip/virtualenv paths and env |
| `rust` | shared `~/.cargo` / `~/.rustup` (or `CARGO_HOME` / `RUSTUP_HOME`) |
| `ssh` | `~/.ssh/config` plus a dedicated agent with `~/.ssh/sandbox_*` keys |
| `term` | `TERM`, `TERMINFO`, `COLORTERM`, `TERM_PROGRAM`, `EDITOR` |
| `xdg-open` | host `xdg-open` via flatpak-xdg-utils |

### CLI

```bash
bk list-features

# Tighten a desktop-ish run
bk run --no-feature gui --no-feature dbus --no-feature xdg-open curl https://example.com

# Minimal toolchains for a script
bk run --no-feature cursor --no-feature google --feature python --feature git python app.py

# Allowlist-style: disable broadly in config, then enable what you need
bk run --feature ssh --feature git git fetch
```

Precedence (later wins for CLI flags): feature defaults → global config
`features` → per-executable `executables.<name>.features` →
`--feature` / `--no-feature`.

### Config

Configuration is read from `~/.config/buddelkiste/config.toml`, then merged with
`.buddelkiste.toml` from the current directory or an ancestor (project values
win). The project file is masked inside the sandbox (empty file bound over the
path) so the sandboxed command cannot read it.

```toml
# Global allowlist (exactly these features), or use a table of overrides:
# features = { gui = false, google = false }
features = ["home", "git", "ssh", "python", "rust", "term", "locale"]

[feature.zig]
description = "Zig toolchain cache"
default = false
env = ["ZIG_GLOBAL_CACHE_DIR"]

[[feature.zig.binds]]
source = "$ZIG_GLOBAL_CACHE_DIR"
mode = "rw"

[[feature.zig.binds]]
source = "${HOME}/.zig"
mode = "ro"

[[feature.zig.binds]]
source = "${HOME}/.cache/zig"
mode = "overlay"   # persistent upper under $XDG_CACHE_HOME/buddelkiste/overlays/<hash>

[executables.cursor-agent]
features = ["cursor", "git", "ssh", "gui", "dbus", "xdg-open", "term"]
args = ["--force"]

[executables.cursor-agent.network]
mode = "filter"
policy = "deny"
allow = ["1.1.1.1/32", "api.github.com"]

[executables.python]
features = { python = true, git = true, gui = false }
shim = false

# Docker proxy: declare images in config, then `bk docker-policy apply`
# (enforcement files live under ~/.config/buddelkiste/docker-proxy/).
[docker_proxy]
images = ["alpine:3.20", "postgres:16-alpine", "ghcr.io/example/*"]
# on_unknown_image = "session"  # default: hold until approve/deny
# on_unknown_image = "deny"     # immediate 403 (good for CI)

# Project-local rootless daemon (docker-instance feature; default off)
# [docker_instance]
# fs = "project"       # host | project | data
# net = "userspace"    # host | userspace | none
# # data_root = "$XDG_DATA_HOME/buddelkiste/docker-instance/myproj"
# # fs_allow = ["$HOME/.cache/go-build"]
# # [docker_instance.policy]
# # images = ["*"]

# shims = false  # disable PATH shims globally (per-entry shim = true still wins)

[[binds]]
source = "/path/to/directory"
mode = "ro"   # or "rw", "tmp-overlay", "overlay", "overlay:$XDG_CACHE_HOME/bk-upper"

[[binds]]
source = "${HOME}/scratch"
target = "/mnt/scratch"
mode = "tmp-overlay"   # writable in the sandbox; host tree unchanged

[[envvars]]
name = "MYENVVAR"
value = "example value"   # omit value= to take it from the process environment

[network]
# Defaults: mode = "filter", policy = "deny",
# deny_presets = ["internal", "localhost"] (RFC1918/ULA + loopback).
mode = "filter"
policy = "deny"
allow = ["1.1.1.1/32", "api.github.com", "*.pypi.org"]
deny = ["203.0.113.0/24"]
deny_presets = ["internal", "localhost", "metadata", "linklocal", "corp"]

[network.presets]
corp = ["10.50.0.0/16", "*.internal.example.com"]
```

Bind `mode` values:

| Mode | Meaning |
|------|---------|
| `ro` | read-only bind (default) |
| `rw` | read-write bind |
| `tmp-overlay` | overlayfs; writes are ephemeral |
| `overlay` | overlayfs; upper under `$XDG_CACHE_HOME/buddelkiste/overlays/<sha256(source)>` |
| `overlay:<path>` | overlayfs with an explicit upper path (`$VAR` / `${VAR}` / `~` ok) |

Paths in `source`, `target`, and `overlay:<path>` may use `$VAR` / `${VAR}`.

The current working directory must be visible inside the sandbox. If it is not
covered by any bind, `bk` asks whether to whitelist it for this run or
permanently (appends a `[[binds]]` entry). Non-interactively it errors instead.

### PATH shims

For each `[executables.<name>]` entry with shimming enabled, `bk shims install`
writes a small `sh` wrapper into `$XDG_BIN_HOME` (default `~/.local/bin`). The
shim resolves the real binary (skipping its own directory) and runs
`bk run <real> "$@"`. Shims include a `# buddelkiste-shim:` marker so later
installs can refresh our own files without overwriting unrelated binaries.

Toggle with a global `shims` boolean (default `true`) and optional per-entry
`shim = true/false` overrides. Disabled entries remove a managed shim on the
next `install`.

```toml
shims = true

[executables.cursor-agent]
features = ["cursor"]

[executables.python]
shim = false
```

```bash
bk shims install   # create/update/remove shims per config
bk shims check     # warn if an original binary appears earlier on PATH
```

Ensure `~/.local/bin` is early on your `PATH`. `bk shims check` exits non-zero
when something would bypass the sandbox.

### Python features (entry points)

Built-ins and third-party packages register features under the
`buddelkiste.features` entry-point group. The entry point value must be a
`Feature` instance, or a zero-argument callable that returns one. When loaded,
`name` and `origin` are set from the entry-point name and value
(e.g. `labs` / `mypkg.features:LABS`).

`Feature` fields:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `name` | `str` | *(required)* | Feature id used in CLI/config (`--feature`, `features = [...]`). Overwritten by the entry-point name at load time. |
| `description` | `str` | *(required)* | One-line summary shown by `bk list-features`. |
| `default` | `bool` | `False` | Whether the feature is enabled before config/CLI overrides. |
| `env_vars` | `tuple[str, ...]` | `()` | Host env var names to forward into the sandbox when the feature is on. |
| `binds` | `Callable[[], list]` | `lambda: []` | Zero-arg callable returning bind objects (`ROBindConfig`, `RWBindConfig`, `DevBindConfig`, overlay configs, `Tmpfs`, or raw bwrap arg tuples). Called each run. |
| `setup` | `Callable[[], AbstractContextManager[Sequence[str]]] \| None` | `None` | Optional factory returning a context manager. Entered while the sandbox runs; its yielded sequence is appended as extra bwrap args (binds, `--setenv`, …). Use for sockets/agents that need lifecycle. |
| `conflicts_with` | `tuple[str, ...]` | `()` | Feature names that must not be enabled together (checked before launch). |
| `origin` | `str` | `""` | Shown in `bk list-features`. Overwritten by the entry-point value at load time (e.g. `mypkg.features:LABS`). |

```python
# mypkg/features.py
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from buddelkiste.binds import ROBindConfig, RWBindConfig
from buddelkiste.features import Feature


def labs_binds() -> list:
    home = Path.home()
    return [
        RWBindConfig(home / ".labs"),
        ROBindConfig(home / ".config/labs"),
    ]


@contextmanager
def labs_setup() -> Iterator[Sequence[str]]:
    # Optional: start helpers, yield extra bwrap args, clean up on exit.
    # Built-in ssh uses this pattern for a dedicated ssh-agent.
    yield []


LABS = Feature(
    name="labs",  # replaced by entry-point name "labs" when loaded
    description="Lab tooling directories",
    default=False,
    env_vars=("LABS_HOME",),
    binds=labs_binds,
    setup=labs_setup,  # or omit / None
    origin="mypkg.features:LABS",  # replaced by entry-point value when loaded
)
```

```toml
# pyproject.toml
[project.entry-points."buddelkiste.features"]
labs = "mypkg.features:LABS"
```

After install, `bk list-features` shows the entry and its origin. Pure-TOML
`[feature.<name>]` covers env/bind cases without a package; use Python entry
points for custom bind logic or `setup` hooks. Config feature names must not
collide with an existing entry point.

## Docker proxy

The raw `docker` feature exposes the host Docker socket. Prefer **`docker-proxy`**
when a sandboxed tool (agent, CI helper, …) should talk to Docker without a full
socket: the host `bk` process runs a filtered API proxy, binds only that socket
into the sandbox, and sets `DOCKER_HOST` to it.

`docker`, `docker-proxy`, and `docker-instance` conflict; enable only one.

### Enable

```bash
# One-off
bk run --no-feature docker --feature docker-proxy docker version

# Or in config (docker-proxy defaults to off)
features = { docker = false, docker-proxy = true }

[executables.cursor-agent]
features = { docker = false, docker-proxy = true }
```

### Policy layers

Effective policy is the merge of, in order:

1. **Host store** — `~/.config/buddelkiste/docker-proxy/<project-key>.toml`
   (per project directory / `.buddelkiste.toml` root)
2. **Session grants** — same dir, `<project-key>.session.toml` (written by
   `bk docker-policy approve`)
3. **Config declaration** — optional `[docker_proxy]` in user/project config
   (used by `apply`; also merged when present)

```bash
bk docker-policy path    # host store path for this project
bk docker-policy show    # effective images + on_unknown_image
bk docker-policy apply   # copy [docker_proxy] from config → host store
bk docker-policy apply --dry-run
```

Declare images in config, then apply once (or edit the host file from `path`):

```toml
[docker_proxy]
images = [
  "alpine:3.20",
  "postgres:16-*",
  "ghcr.io/myorg/*",
]
# Optional; default is "session"
# [docker_proxy.approval]
# on_unknown_image = "deny"
```

Image patterns use shell-style globs (`fnmatch`). A pattern ending in `:*` also
matches the untagged name (Docker’s implied `:latest`). Digests are stripped
before matching (`repo:tag@sha256:…` → `repo:tag`).

### What the proxy allows and denies

Forwarded by default: ordinary Engine API traffic for allowlisted images
(create/start/attach/pull of listed refs, `version`, `info`, …).

Denied by default (403), even for allowlisted images:

- Dangerous `HostConfig` — privileged, host network/PID/IPC/UTS/userns,
  `CapAdd`, device mounts, …
- Host bind mounts unless the source matches `allow_binds` globs in the policy
- API categories: build, commit, swarm, plugins, session

Unknown images (not on the allowlist):

| `on_unknown_image` | Behaviour |
|--------------------|-----------|
| `session` (default) | Hold the HTTP request until you approve or deny on the **host** |
| `deny` | Immediate 403 (suitable for CI) |

### Interactive approval (host only)

With `on_unknown_image = "session"` (the default), unknown images are **not**
prompted on the sandboxed client’s TTY. Approval is an out-of-band host
workflow so agent/CI sessions keep a clean shared terminal.

**Flow**

1. Inside the sandbox, a client does something that needs an unknown image
   (e.g. `docker pull alpine:3.21` or `docker run …`).
2. The proxy **holds** the HTTP request (the client blocks / waits). Concurrent
   waits for the same image share one pending entry.
3. On the host, the proxy logs the hold and (best-effort) shows a desktop
   notification via `notify-send`, including the pending id and a ready-to-run
   `bk docker-policy approve <id>` hint.
4. On the **host** (another terminal, outside the sandbox), decide:

```bash
bk docker-policy pending              # id<TAB>image
bk docker-policy approve              # if exactly one pending
bk docker-policy approve alpine:3.21  # by image or pending id
bk docker-policy deny deadbeef
```

5. **Approve** appends the image to the session policy file
   (`…/<project-key>.session.toml`), unblocks waiters, and lets the original
   create/pull continue (HostConfig / API denials still apply).
6. **Deny** (or proxy teardown) unblocks with 403.

The control socket is **not** mounted into the sandbox — `pending` /
`approve` / `deny` only work on the host while that project’s proxy is live
(see `…/<key>.runtime.json`).

**If you miss the notification**

- `notify-send` missing or failing → proxy logs a warning with the same
  `approve` command; use `bk docker-policy pending` or the proxy logs.
- Session grants last for that project’s proxy lifetime / session file;
  promote durable allowlists with `[docker_proxy]` + `bk docker-policy apply`
  (or edit the host store from `bk docker-policy path`).

### Operational notes

- Live proxy metadata: `~/.config/buddelkiste/docker-proxy/<key>.runtime.json`
  (pid, control socket path). Cleared when the sandbox exits.
- The proxy only supports `unix://` Docker sockets (`DOCKER_HOST` on the host).
- Socket paths are kept short enough for `AF_UNIX` (including a sibling `.ctl`
  control socket).

## Docker instance

**`docker-instance`** starts a temporary **rootless** `dockerd` with a dedicated
store for this project, then (by default) puts the filtered API proxy in front
and binds only that socket into the sandbox. Images and volumes live under
`$XDG_DATA_HOME/buddelkiste/docker-instance/<project-key>/` (override with
`data_root`) and do not touch the user-global Docker engine.

Requires: `dockerd`, `rootlesskit`, `newuidmap`/`newgidmap`, `/etc/subuid` and
`/etc/subgid` entries for your user; for `net = "userspace"` also `pasta`
(passt) or `slirp4netns`. `fuse-overlayfs` is recommended for storage.

```bash
bk run --no-feature docker --feature docker-instance docker version
```

```toml
features = { docker = false, docker-instance = true }

[docker_instance]
fs = "project"          # host | project | data — daemon mount namespace
net = "userspace"       # host | userspace | none
# data_root = "/path/to/store"
# fs_allow = ["$HOME/.cache/go-build"]
proxy = true            # agent sees only the filtered proxy socket

# Optional; defaults allow build + /session and images=["*"] on this private daemon
# [docker_instance.policy]
# images = ["*"]
# [docker_instance.policy.api]
# deny = ["commit", "swarm", "plugins"]
```

| `fs` | Daemon can see |
|------|----------------|
| `host` | Full host filesystem (store still isolated) |
| `project` (default) | Project root, `data_root`, `fs_allow`, minimal system paths |
| `data` | `data_root` + `fs_allow` + minimal system only |

| `net` | Behaviour |
|-------|-----------|
| `userspace` (default) | rootlesskit pasta/slirp4netns; dockerd iptables+forward on so bridge containers can use DNS/egress |
| `host` | Share host network with the daemon helper |
| `none` | No network for the daemon helper |

HostConfig denials (privileged, host net, CapAdd, arbitrary binds, …) still
apply when `proxy = true`. Unlike host `docker-proxy`, instance policy defaults
**allow** `docker build` and BuildKit `/session`, and use `images = ["*"]` on
this private store. BuildKit via the Docker CLI also needs a working
`docker-buildx` plugin on the host; without it, install buildx or use
`DOCKER_BUILDKIT=0` for the legacy builder.

## Network filter dependencies

`network.mode = "filter"` needs **pasta** (from `passt`) or **slirp4netns**, plus
**nft** and **setpriv**. No root and no reserved host subnets are required.
Hostname rules start a DNS proxy that redirects UDP/53 and updates dynamic
nftables allow sets from resolved A/AAAA records. Nameserver IPs from
`/etc/resolv.conf` are auto-allowed under a default-deny policy.

## Development

```bash
uv sync --group dev
uv run bk --help
uv run pytest                 # unit + nested-safe integ + coverage; TUN/docker e2e skipped if unavailable
uv run pytest -m integration  # real bwrap host/none + nested nft
uv run pytest -m requires_tun # filter/pasta e2e (needs /dev/net/tun)
uv run pytest -m requires_docker  # docker-proxy e2e (host Docker; skipped inside bwrap)
uv run pytest -m requires_rootless_docker  # docker-instance e2e (needs rootlesskit)
```

Integration layout:

- `tests/` — unit/contract tests (mocked subprocess where needed)
- `tests/integ/` — nested-safe real `bwrap` (`host`/`none`), binds/env isolation, nested `nft` + DNS proxy/`nft add element`/`UDP/53` redirect against real tools
- `tests/integ_net/` — filter-mode e2e via pasta/slirp (allow/deny IP & host, guest caps); skipped without `/dev/net/tun`
- `tests/integ_docker/` — docker-proxy / docker-instance e2e; skipped inside bwrap or without Docker / rootlesskit
