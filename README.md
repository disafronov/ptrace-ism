# ptrace-ism

A standalone raw-ptrace process tracer for Linux x86_64. It execs a target
command as its own child and ptraces it, observing successful exec events
across the entire process tree (fork / vfork / clone), then applies an
argv-based deny policy before the new program enters user space. A denied
tracee is killed before it runs its own code.

> **Not a security boundary.** ptrace-ism is a guardrail against accidental
> agent actions, not a hardened sandbox for hostile code. It evaluates argv
> from `/proc/pid/cmdline` after a successful exec event. A process that wants
> to evade the policy can choose a different executable, change argv, or use
> another unblocked path. Enforcement is not kernel-level isolation; do not
> rely on it to contain malicious code.

## Requirements

- Linux x86_64
- Python 3 (stdlib only)
- ptrace access: PTRACE_TRACEME from a traced child is not affected by
  kernel.yama.ptrace_scope

## Install

Place the script on PATH and make it executable:

    install -m 0755 ptrace-ism ~/bin/ptrace-ism

## Usage

    ptrace-ism <command> [args...]
    ptrace-ism git push
    ptrace-ism bash -c 'git push && echo done'

## Activation

`ptrace-ism` uses `ptrace` only when the caller asks it to enforce policy or
observe a process. Otherwise it replaces itself with the target via a direct
`execvp`, with no tracing overhead and no `ptrace-ism` output.

- A config with at least one deny rule enables enforcement: deny events and a
  summary are written to stderr. Missing, empty, and allow-only configs do not
  activate tracing.
- `PTRACE_ISM_DEBUG=1` enables interactive observation: diagnostics, exec
  events, and a summary are written to stderr, even without a config.
- `PTRACE_ISM_TRACE_FILE=<path>` enables audit recording: events and the
  summary are appended to the file, even without a config. Deny events remain
  visible on stderr; the terminal is otherwise quiet.
- When both debug and trace file are set, events go to both destinations.

Environment:

- `PTRACE_ISM_CONFIG` — path to rules JSON (default `~/.config/ptrace-ism.json`)
- `PTRACE_ISM_TRACE_FILE` — append the full trace to a file
- `PTRACE_ISM_DEBUG=1` — verbose trace and diagnostics to stderr (takes
  effect only when set to exactly `1`)
- `PTRACE_ISM_TIMEOUT` — OPT-IN run timeout in seconds (default: off). The
  timeout is disabled unless the variable is set to a positive number:
  absent, `0`, a negative value, or an invalid value all mean "no timeout" —
  the traced command runs as long as it needs. When active, expiry kills the
  traced process tree and exits 124.

## Configuration

Default `~/.config/ptrace-ism.json`:

    {
      "git": [
        [],
        [["status"], "allow"],
        [["push"]],
        [["push", "--dry-run"], "allow"]
      ],
      "rm": []
    }

The top-level object maps an application basename to its policy. The application
is matched against the basename of `argv[0]`; `argv` is never converted into a
command string. A missing application has no policy and is allowed.

- `"rm": []` denies every `rm` invocation.
- Within a non-empty rule list, `[]` is a universal deny.
- `[pattern]` denies; `[pattern, "allow"]` or `[pattern, "deny"]` uses the
  stated action. Patterns are non-empty arrays of strings.
- All matching patterns are compared by length; the longest wins. Equal-length
  matches with different actions are a configuration error.
- `[[]]` is invalid: `application: []` is the sole spelling for a policy that
  denies every invocation.

Patterns match as ordered subsequences anywhere in `argv[1:]`, so `["push"]`
matches both `git push origin main` and `git -C repo push origin main`.
`["reset", "--hard"]` matches `git reset --quiet --hard HEAD`.

There are no built-in deny rules:

- Missing config file: no deny rules, everything is allowed.
- A completely empty config file (0 bytes or whitespace-only) or `{}`: no
  policy, everything is allowed.
- Invalid JSON, an unreadable config file, a non-object config, or malformed
  policy rules: the tool refuses to run and exits non-zero with an error naming
  the config path and the problem.

## Behavior notes

- A denied exec has completed in the kernel, but is stopped before the new
  program can execute user-space instructions; ptrace-ism sends it `SIGKILL`.
  The corresponding process status is normally 137.
- Nested tracing is impossible by kernel semantics: an already-traced child
  cannot PTRACE_TRACEME again (outer tracer keeps claiming descendants).
- A traced run emits one `[ptrace-ism] summary` line (`exec_events`, `denied`,
  `elapsed`, `root_exit`) to stderr, except trace-file-only mode, where it is
  written to the trace file.

Exit codes:

- `2` — usage error (no command given)
- `124` — run timeout (when `PTRACE_ISM_TIMEOUT` is set and exceeded)
- `127` — command not found / exec fails

## Development

    make test       # syntax + unit tests (no ptrace needed)
    make storm      # 40 storm tests: ptrace-ism wrapper under a fork/exec storm

Full target list: `all`, `test`, `syntax`, `unit`, `storm`, `clean` (see the
Makefile for what each runs).

`make storm` runs the 40 storm tests in `tests/test_storm_*.py` with pytest-xdist
(`pytest -n 16`). Each file executes the `ptrace-ism` wrapper around a command
(`/usr/bin/uname -p`, `/bin/echo x`) with debug enabled and asserts the tool's
`[ptrace-ism] summary` stderr line, so the storm fires 80 real ptrace-ism
invocations. It must run on a real host: the storm tests use ptrace through the
tool, which may be restricted in containers and sandboxes.

`make storm` needs pytest and pytest-xdist:
`python3 -m pip install pytest pytest-xdist`
