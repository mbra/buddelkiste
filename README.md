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
`[executables.<name>.network]` for IP/CIDR and hostname filtering. See `bk --help`.

### Filter mode dependencies

`network.mode = "filter"` needs **pasta** (from `passt`) or **slirp4netns**, plus
**nft** and **setpriv**. No root and no reserved host subnets are required.
Hostname rules start a DNS proxy that redirects UDP/53 and updates dynamic
nftables allow sets from resolved A/AAAA records.

## Development

```bash
uv sync
uv run bk --help
uv run pytest
```
