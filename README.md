# ptrace-ism

A standalone raw-ptrace process tracer for Linux x86_64. It execs a target
command as its own child and ptraces it, observing every execve(2)/execveat(2)
syscall entry across the entire process tree (fork / vfork / clone), applies an
argv-based deny policy, and blocks matching execs at the syscall entry.

Python 3 stdlib only. A from-scratch replacement for an earlier GDB-based
engine (which lost seccomp dispatch under fork/exec storms).

## Requirements

- Linux x86_64
- Python 3 (stdlib only)
- ptrace access: PTRACE_TRACEME from a traced child is not affected by
  kernel.yama.ptrace_scope

## Install

Place the script on PATH and make it executable:

    install -m 0755 ptrace-ism ~/bin/ptrace-ism

## Usage

    ptrace-ism [options] -- <command> [args...]
    ptrace-ism git push
    ptrace-ism bash -c 'git push && echo done'

Environment:

- `PTRACE_ISM_CONFIG` — path to rules JSON (default `~/.config/ptrace-ism.json`)
- `PTRACE_ISM_TRACE_FILE` — append the full trace to a file
- `PTRACE_ISM_DEBUG=1` — verbose trace and diagnostics to stderr
- `PTRACE_ISM_TIMEOUT` — seconds before teardown

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

## Development

    make test       # syntax + unit tests (no ptrace needed)
    make storm      # fork/exec storm test with pytest-xdist

`make storm` must run on a real host: ptrace may be restricted in containers
and sandboxes.
