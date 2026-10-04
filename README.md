# buddelkiste

Run a command inside a [bubblewrap](https://github.com/containers/bubblewrap) sandbox (`bk`).

## Usage

```bash
# Run a command in the sandbox
bk /path/to/executable [args...]

# Inspect the sandbox (login shell)
bk
```

Wrapper option: `--debug` (enable debug logging). Everything else is the sandboxed command.

Configuration: `~/.config/buddelkiste/config.toml` (optional binds and envvars). See `bk --help`.

## Development

```bash
uv sync
uv run bk --help
```
