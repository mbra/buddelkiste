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
```

Wrapper options: `--debug`, `--feature` / `--no-feature`, `--list-features`.
Everything else is the sandboxed command.

Configuration: `~/.config/buddelkiste/config.toml` (features, binds, envvars). See `bk --help`.

## Development

```bash
uv sync
uv run bk --help
uv run pytest
```
