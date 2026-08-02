#!/usr/bin/env python3
"""Unit tests for ptrace-ism config loading and the argv matcher.

Import-based (no ptrace): runs anywhere Python 3 is available. The script is
loaded by path via an explicit SourceFileLoader (its filename contains a
hyphen and has no .py suffix, so it cannot be imported by name and the
default loader lookup by suffix would fail). Each case resets the module-level
config cache and points PTRACE_ISM_CONFIG at a temp file, so cases are
independent.
"""
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_loader = importlib.machinery.SourceFileLoader("ptrace_ism", str(ROOT / "ptrace-ism"))
spec = importlib.util.spec_from_file_location("ptrace_ism", loader=_loader)
assert spec is not None and spec.loader is not None
ptrace_ism = importlib.util.module_from_spec(spec)
# Register in sys.modules before exec: the module's @dataclass(slots=True)
# classes resolve field annotations via sys.modules, which would be None
# otherwise. This mirrors the importlib.util.module_from_spec() docs flow.
sys.modules["ptrace_ism"] = ptrace_ism
spec.loader.exec_module(ptrace_ism)  # main() is guarded by __name__ == "__main__"


def reset_config() -> None:
    ptrace_ism._deny_rules = None


def write_config(payload: object) -> str:
    fd, path = tempfile.mkstemp(
        prefix="ptrace-ism-test-", suffix=".json", dir=str(ROOT)
    )
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


def event(argv: list[str]) -> ptrace_ism.ExecEvent:
    argv = list(argv)
    path = argv[0] if argv else ""
    return ptrace_ism.ExecEvent(
        pid=1,
        syscall="execve",
        path=path,
        argv=tuple(argv),
        argv0=path,
    )


def decide_argv(argv: list[str]) -> str:
    reset_config()
    return ptrace_ism.decide(event(argv))


def check(name: str, got: str, want: str) -> None:
    ok = got == want
    print(f"[{'ok' if ok else 'FAIL'}] {name}: got {got!r}, want {want!r}")
    if not ok:
        raise SystemExit(1)


def main() -> int:
    # Custom config: deny git push, allow everything else.
    cfg = write_config({"deny": [["git", "push"]]})
    os.environ["PTRACE_ISM_CONFIG"] = cfg
    try:
        check("deny git push", decide_argv(["git", "push"]), "deny")
        check(
            "deny git push origin main (prefix)",
            decide_argv(["git", "push", "origin", "main"]),
            "deny",
        )
        check(
            "deny /usr/bin/git push (basename argv0)",
            decide_argv(["/usr/bin/git", "push"]),
            "deny",
        )
        check("allow git pull", decide_argv(["git", "pull"]), "allow")
        check("allow git status", decide_argv(["git", "status"]), "allow")
        check("allow bash -c", decide_argv(["bash", "-c", "echo hi"]), "allow")
    finally:
        os.unlink(cfg)

    # Missing config -> built-in fallback still denies git push (fail-closed).
    os.environ.pop("PTRACE_ISM_CONFIG", None)
    check("fallback deny git push (no config)", decide_argv(["git", "push"]), "deny")
    check("fallback allow git pull (no config)", decide_argv(["git", "pull"]), "allow")

    # Broken JSON -> fallback (fail-closed).
    fd, cfg2 = tempfile.mkstemp(
        prefix="ptrace-ism-broken-", suffix=".json", dir=str(ROOT)
    )
    os.write(fd, b"{not json")
    os.close(fd)
    os.environ["PTRACE_ISM_CONFIG"] = cfg2
    try:
        check("broken config falls back to deny", decide_argv(["git", "push"]), "deny")
    finally:
        os.unlink(cfg2)

    print("OK: all matcher unit tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
