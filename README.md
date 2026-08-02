# ptrace-ism

A standalone raw-ptrace process tracer for Linux x86_64. It execs a target
command as its own child and ptraces it, observing every execve(2)/execveat(2)
syscall entry across the entire process tree (fork / vfork / clone), applies an
argv-based deny policy, and denies matching execs: the root command is refused
before exec (exit 126), descendant execs are blocked at the syscall entry.

Python 3 stdlib only. A from-scratch replacement for an earlier GDB-based
engine (which lost seccomp dispatch under fork/exec storms).

> **Disclaimer: PROTOTYPE, not a security boundary.** ptrace-ism is a
> demonstration/PROTOTYPE for A/B validation, not a hardened security sandbox.
> Its deny decision is based on argv read from the tracee's memory via
> `/proc/pid/mem`, which is a classic time-of-check/time-of-use (TOCTOU) race
> between check and exec. The matching (basename argv[0] plus a prefix) can be
> trivially bypassed, for example with global git options such as `git -C` or
> execvp argv[0] tricks. Enforcement rewrites the exec path or the syscall
> number and is not kernel-level isolation. Do not rely on it as a security
> boundary in production.

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

    {"deny": [["git", "push"]]}

Schema: `{"deny": [[argv0, arg1, ...], ...]}`. Matching is prefix-based and
argv[0] is compared by basename, so `["git", "push"]` also blocks
`git push origin main` and `/usr/bin/git push ...`.

There are no built-in deny rules:

- Missing config file: no deny rules, everything is allowed.
- A completely empty config file (0 bytes or whitespace-only), an empty `deny`
  list (or a config whose rules are all invalid): no deny rules, everything is
  allowed.
- Invalid JSON, an unreadable config file, or valid JSON that is not an
  object: the tool refuses to run and exits non-zero with an error naming the
  config path and the problem.

## Behavior notes

- Denied root command: the child exits 126 before exec; `&&` / `set -e`
  chains break, `;` continues.
- Denied descendant exec: the exec path is replaced with a tiny stub that
  silently exits 126 (fallbacks: EACCES path rewrite, ENOSYS syscall number).
- Nested tracing is impossible by kernel semantics: an already-traced child
  cannot PTRACE_TRACEME again (outer tracer keeps claiming descendants).
- Every normal run emits one `[ptrace-ism] summary` line to stderr
  (`exec_events`, `denied`, `elapsed`, `root_exit`).

Exit codes:

- `2` — usage error (no command given)
- `124` — run timeout (when `PTRACE_ISM_TIMEOUT` is set and exceeded)
- `126` — root command denied (found but not executed)
- `127` — command not found / exec fails (other than EACCES/ENOSYS)

## Development

    make test       # syntax + unit tests (no ptrace needed)
    make storm      # 40 storm tests: ptrace-ism wrapper under a fork/exec storm

Full target list: `all`, `test`, `syntax`, `unit`, `storm`, `clean` (see the
Makefile for what each runs).

`make storm` runs the 40 storm tests in `tests/test_storm_*.py` with pytest-xdist
(`pytest -n 16`). Each file executes the `ptrace-ism` wrapper around a command
(`/usr/bin/uname -p`, `/bin/echo x`) and asserts the tool's `[ptrace-ism] summary`
stderr line, so the storm fires 80 real ptrace-ism invocations. It must run on a
real host: the storm tests use ptrace through the tool, which may be restricted
in containers and sandboxes.

`make storm` needs pytest and pytest-xdist:
`python3 -m pip install pytest pytest-xdist`
