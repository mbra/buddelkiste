# Agent notes

## Running tests

Prefer ``just test`` (with optional pytest args after ``--``) over invoking
``uv run pytest`` directly. Example::

   just test tests/test_docker_proxy.py -q --cov=buddelkiste.docker_proxy

## Lint and typecheck before commit

Before creating a commit, run both and fix any findings::

   just lint
   just typecheck

- ``just lint`` — ``ruff check`` on ``src``, ``tests``, and ``scripts``
- ``just typecheck`` — ``ty check`` on ``src``

Do not commit with known ruff or ty failures. Extra args go after ``--``
(e.g. ``just lint -- --fix``).

## Commit message style

- Subject: imperative, specific about the change; at most 100 characters.
- Body: more verbose than a one-liner—say *why* and what areas moved
  (modules, CLI, tests), not only “fix X” / “update Y”.
- Wrap all lines at **at most 100 characters**.
- Prefer a short paragraph or a few sentences over bullet spam unless the
  change is a list of unrelated items.
- Keep Co-authored-by trailers if the tooling already added them; do not
  invent trailers.

Example shape::

   Hold unknown docker-proxy images until CLI approve or deny.

   Default on_unknown_image to "session": park create/pull requests, expose a
   control socket plus runtime metadata, and add bk docker-policy
   pending/approve/deny so operators can grant session access from a separate
   host terminal without touching the agent TTY.

## Continuous host test feedback (`scripts/debug-loop`)

When iterating on failures that must run **outside** the agent sandbox (e.g.
`requires_docker`, real Docker socket, or other host-only probes), use the
debug-loop watcher instead of asking the user to paste logs each time.

### Setup

1. Agent starts the watcher in the background from the repo root:

   ```bash
   uv run python scripts/debug-loop debug.log
   ```

2. User (or host CI) pipes a full test run through ``tee`` so output stays
   visible on the terminal while also landing in that file:

   ```bash
   pytest … 2>&1 | tee debug.log
   # or: just test 2>&1 | tee debug.log
   ```

3. On each rewrite (`tee` close / atomic replace), the watcher prints:

   ```
   ===== DEBUG.LOG UPDATE (close_write) =====
   …
   ===== END DEBUG.LOG UPDATE (close_write) =====
   ```

4. Agent awaits that banner (`AwaitShell` / `notify_on_output` on
   `===== DEBUG.LOG UPDATE` or `===== END DEBUG.LOG UPDATE`), reports findings,
   and continues fixing **without** re-prompting the user.

5. When the suite is green (or the debug-loop work is otherwise finished),
   **stop the watcher** — do not leave it running. Example::

   ```bash
   pkill -f 'scripts/debug-loop' 2>/dev/null || true
   ```

### Behaviour notes

- Watches **CLOSE_WRITE** and **MOVED_TO** only (not `MODIFY`), so progressive
  pytest writes do not spam mid-run dumps.
- Dumps at most the last ~200k characters of `debug.log`.
- Default path is `debug.log` in the cwd; pass another path as the first arg.
- Stopping is the agent's job after success; the user should not have to ask.

### Do not

- Do not treat a mid-run truncate of `debug.log` as a finished suite; wait for
  the `END DEBUG.LOG UPDATE` banner after the `tee` pipeline exits.
- Do not require the user to paste the same log into chat if the watcher is
  already running.
- Do not keep `debug-loop` running after tests succeed.
