# buddelkiste

Run a command inside a [bubblewrap](https://github.com/containers/bubblewrap) sandbox (`bk`).

## Usage

```bash
# Run a command in the sandbox
bk /path/to/executable [args...]

# Inspect the sandbox (login shell)
bk

# Topic features (all on by default)
bk --list-features
bk --no-feature gui --no-feature google cursor-agent
bk --feature python --feature ssh python myscript.py

# Network modes
bk --network host …                 # share host network (default)
bk --network none …                 # no connectivity
bk --network filter \
  --net-policy deny \
  --net-allow 1.1.1.1/32 \
  --net-allow api.github.com \
  --net-allow '*.pypi.org' \
  --net-deny-preset metadata \
  --net-deny-preset private …
bk --list-net-presets
```

Wrapper options: `--debug`, `--feature` / `--no-feature`, `--list-features`,
`--network`, `--net-policy`, `--net-allow`, `--net-deny`, `--net-deny-preset`,
`--list-net-presets`. Everything else is the sandboxed command.

Configuration (`~/.config/buddelkiste/config.toml`) can set a global feature list/table,
per-executable overrides under `[executables.<name>]`, and `[network]` /
`[executables.<name>.network]` for IP/CIDR and hostname filtering. Custom deny
presets go under `[network.presets]`. Custom features go under `[feature.<name>]`
with `env` allowlists and `binds` (paths may use `$VAR` / `${VAR}`; bind
`mode` is `ro` (default), `rw`, `tmp-overlay`, `overlay`, or `overlay:<path>`).
Installed
packages can register features via the `buddelkiste.features` entry-point group.
`--list-features` shows each feature's module path. See `bk --help`.

### Filter mode dependencies

`network.mode = "filter"` needs **pasta** (from `passt`) or **slirp4netns**, plus
**nft** and **setpriv**. No root and no reserved host subnets are required.
Hostname rules start a DNS proxy that redirects UDP/53 and updates dynamic
nftables allow sets from resolved A/AAAA records.

## Development

```bash
uv sync
uv run bk --help
uv run pytest                 # unit + nested-safe integ + coverage; TUN e2e skipped if unavailable
uv run pytest -m integration # real bwrap host/none + nested nft
uv run pytest -m requires_tun # filter/pasta e2e (needs /dev/net/tun)
```


Integration layout:

- `tests/` — unit/contract tests (mocked subprocess where needed)
- `tests/integ/` — nested-safe real `bwrap` (`host`/`none`), binds/env isolation, nested `nft`
- `tests/integ_net/` — filter-mode e2e via pasta/slirp; skipped without `/dev/net/tun`
