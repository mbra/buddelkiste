set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Create .venv and install the package with the dev dependency group (expects uv).
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    if ! command -v uv >/dev/null 2>&1; then
        echo "uv is required on PATH" >&2
        exit 1
    fi
    uv sync --group dev

# Tag and build the next release candidate (omit version to be prompted).
rc *args:
    "{{justfile_directory()}}/scripts/release" --rc {{args}}

# Tag and build a release (omit version to be prompted with recent commits).
release *args:
    "{{justfile_directory()}}/scripts/release" {{args}}
