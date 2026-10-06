# Agent notes

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

### Behaviour notes

- Watches **CLOSE_WRITE** and **MOVED_TO** only (not `MODIFY`), so progressive
  pytest writes do not spam mid-run dumps.
- Dumps at most the last ~200k characters of `debug.log`.
- Default path is `debug.log` in the cwd; pass another path as the first arg.
- Stop the watcher when the loop is done (`Ctrl-C` / kill the background job).

### Do not

- Do not treat a mid-run truncate of `debug.log` as a finished suite; wait for
  the `END DEBUG.LOG UPDATE` banner after the `tee` pipeline exits.
- Do not require the user to paste the same log into chat if the watcher is
  already running.
