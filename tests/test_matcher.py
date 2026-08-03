#!/usr/bin/env python3
"""Unit tests for ptrace-ism config loading, the argv matcher, and OPT-IN
timeout parsing.

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


def parse_timeout(raw: str | None) -> float:
    """Call ptrace_ism._parse_timeout() with a controlled PTRACE_ISM_TIMEOUT.

    ``None`` means the env var is unset. The caller's env var is restored
    afterwards so timeout cases cannot leak into config cases (or vice versa).
    """
    saved = os.environ.get("PTRACE_ISM_TIMEOUT")
    if raw is None:
        os.environ.pop("PTRACE_ISM_TIMEOUT", None)
    else:
        os.environ["PTRACE_ISM_TIMEOUT"] = raw
    try:
        return ptrace_ism._parse_timeout()
    finally:
        if saved is None:
            os.environ.pop("PTRACE_ISM_TIMEOUT", None)
        else:
            os.environ["PTRACE_ISM_TIMEOUT"] = saved


def expect_refused(name: str, argv: list[str]) -> None:
    """Assert the tool refuses to run: SystemExit with a non-zero exit code.

    Also asserts the refusal is NOT a silent allow: a normal decide() return
    (any decision) fails the test.
    """
    reset_config()
    try:
        got = ptrace_ism.decide(event(argv))
    except SystemExit as exc:
        code = exc.code
        ok = code not in (None, 0) and (
            not isinstance(code, str) or "config" in code
        )
        print(
            f"[{'ok' if ok else 'FAIL'}] {name}: refused with "
            f"SystemExit({code!r})"
        )
        if not ok:
            raise SystemExit(1)
        return
    raise SystemExit(f"[FAIL] {name}: did not refuse; decided {got!r}")


def check(name: str, got: object, want: object) -> None:
    ok = got == want
    print(f"[{'ok' if ok else 'FAIL'}] {name}: got {got!r}, want {want!r}")
    if not ok:
        raise SystemExit(1)


def main() -> int:
    # Custom config: deny argument patterns of the named application.
    cfg = write_config(
        {"deny": {"git": [["push"], ["reset", "--hard"], ["clean"]]}}
    )
    os.environ["PTRACE_ISM_CONFIG"] = cfg
    try:
        check("deny git push", decide_argv(["git", "push"]), "deny")
        check(
            "deny git push origin main",
            decide_argv(["git", "push", "origin", "main"]),
            "deny",
        )
        check(
            "deny /usr/bin/git push (basename argv0)",
            decide_argv(["/usr/bin/git", "push"]),
            "deny",
        )
        check(
            "deny git push after global options",
            decide_argv(["git", "-C", "repo", "--no-pager", "push"]),
            "deny",
        )
        check(
            "deny git reset hard after options",
            decide_argv(["git", "reset", "--quiet", "--hard", "HEAD"]),
            "deny",
        )
        check(
            "allow inverted git reset hard arguments",
            decide_argv(["git", "--hard", "reset", "HEAD"]),
            "allow",
        )
        check("allow git pull", decide_argv(["git", "pull"]), "allow")
        check("allow git status", decide_argv(["git", "status"]), "allow")
        check("allow bash -c", decide_argv(["bash", "-c", "echo hi"]), "allow")
    finally:
        os.unlink(cfg)

    # An empty application rule denies it regardless of its arguments.
    cfg_application = write_config({"deny": {"rm": []}})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_application
    try:
        check("deny rm without arguments", decide_argv(["rm"]), "deny")
        check("deny rm with arguments", decide_argv(["rm", "-rf", "tmp"]), "deny")
    finally:
        os.unlink(cfg_application)

    # Empty config {"deny": {}} -> no deny rules -> allow all.
    cfg_empty = write_config({"deny": {}})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_empty
    try:
        check(
            "allow git push (empty deny mapping)",
            decide_argv(["git", "push"]),
            "allow",
        )
        check(
            "allow git pull (empty deny mapping)",
            decide_argv(["git", "pull"]),
            "allow",
        )
    finally:
        os.unlink(cfg_empty)

    # Completely empty config file (0 bytes or whitespace-only) -> no deny
    # rules -> allow all; it must NOT be treated as broken/invalid JSON, so
    # the tool must NOT refuse to run (a SystemExit here would fail the test).
    fd, cfg_empty_file = tempfile.mkstemp(
        prefix="ptrace-ism-empty-", suffix=".json", dir=str(ROOT)
    )
    os.write(fd, b" \t\n  ")
    os.close(fd)
    os.environ["PTRACE_ISM_CONFIG"] = cfg_empty_file
    try:
        check(
            "allow git push (empty config file)",
            decide_argv(["git", "push"]),
            "allow",
        )
        # Truly 0-byte file: truncate the same config and re-decide.
        with open(cfg_empty_file, "w", encoding="utf-8"):
            pass
        check(
            "allow git push (0-byte config file)",
            decide_argv(["git", "push"]),
            "allow",
        )
    finally:
        os.unlink(cfg_empty_file)
        os.environ.pop("PTRACE_ISM_CONFIG", None)

    # Missing config (env unset, default file absent) -> no deny rules, allow all.
    # Isolate from any real ~/.config/ptrace-ism.json on the machine: the
    # default path is $HOME/.config/ptrace-ism.json, so temporarily point HOME
    # at a fresh empty temp dir (no .config -> FileNotFoundError -> rules {}).
    os.environ.pop("PTRACE_ISM_CONFIG", None)
    saved_home = os.environ.get("HOME")
    temp_home = tempfile.mkdtemp(prefix="ptrace-ism-home-")
    os.environ["HOME"] = temp_home
    try:
        check(
            "allow git push (no config)",
            decide_argv(["git", "push"]),
            "allow",
        )
        check(
            "allow git pull (no config)",
            decide_argv(["git", "pull"]),
            "allow",
        )
    finally:
        if saved_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = saved_home
        # decide_argv() already resets the config cache per call; reset again
        # so no later case inherits rules loaded under the temp HOME.
        reset_config()
        try:
            os.rmdir(temp_home)
        except OSError:
            pass

    # PTRACE_ISM_CONFIG pointing at a nonexistent file -> allow all (no rules).
    nonexistent = str(ROOT / "no-such-ptrace-ism-config.json")
    try:
        os.unlink(nonexistent)
    except FileNotFoundError:
        pass
    os.environ["PTRACE_ISM_CONFIG"] = nonexistent
    try:
        check(
            "allow git push (nonexistent config path)",
            decide_argv(["git", "push"]),
            "allow",
        )
    finally:
        os.environ.pop("PTRACE_ISM_CONFIG", None)

    # Broken JSON -> the tool refuses to run (SystemExit); it must NOT silently
    # allow.
    fd, cfg2 = tempfile.mkstemp(
        prefix="ptrace-ism-broken-", suffix=".json", dir=str(ROOT)
    )
    os.write(fd, b"{not json")
    os.close(fd)
    os.environ["PTRACE_ISM_CONFIG"] = cfg2
    try:
        expect_refused("broken config refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg2)

    # Valid JSON that is not an object -> refuses to run (SystemExit).
    cfg_list = write_config([1, 2, 3])
    os.environ["PTRACE_ISM_CONFIG"] = cfg_list
    try:
        expect_refused("non-object config refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg_list)

    # A malformed deny mapping must not silently disable the policy.
    cfg_bad_deny = write_config({"deny": []})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_bad_deny
    try:
        expect_refused("non-mapping deny refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg_bad_deny)

    # PTRACE_ISM_TIMEOUT: OPT-IN run timeout. Unset/empty/0/negative/invalid
    # -> disabled (0.0); a positive number -> active with that many seconds.
    check("timeout unset -> disabled", parse_timeout(None), 0.0)
    check("timeout empty -> disabled", parse_timeout(""), 0.0)
    check("timeout 0 -> disabled", parse_timeout("0"), 0.0)
    check("timeout negative -> disabled", parse_timeout("-5"), 0.0)
    check("timeout invalid -> disabled", parse_timeout("abc"), 0.0)
    check("timeout positive int", parse_timeout("10"), 10.0)
    check("timeout positive float", parse_timeout("2.5"), 2.5)

    timer_calls: list[tuple[object, ...]] = []
    original_signal = ptrace_ism.signal.signal
    original_setitimer = ptrace_ism.signal.setitimer
    ptrace_ism.signal.signal = lambda sig, handler: timer_calls.append(
        ("signal", sig, handler)
    ) or "previous-handler"
    ptrace_ism.signal.setitimer = lambda which, seconds: timer_calls.append(
        ("setitimer", which, seconds)
    )
    try:
        previous_handler = ptrace_ism._arm_timeout(0.25)
        ptrace_ism._disarm_timeout(previous_handler)
        check(
            "timeout arms precise wall timer",
            timer_calls[1],
            ("setitimer", ptrace_ism.signal.ITIMER_REAL, 0.25),
        )
        check(
            "timeout disarms wall timer",
            timer_calls[2],
            ("setitimer", ptrace_ism.signal.ITIMER_REAL, 0.0),
        )
        check(
            "timeout restores previous handler",
            timer_calls[3],
            ("signal", ptrace_ism.signal.SIGALRM, "previous-handler"),
        )
    finally:
        ptrace_ism.signal.signal = original_signal
        ptrace_ism.signal.setitimer = original_setitimer

    check(
        "ptrace options kill tracees when tracer exits",
        bool(ptrace_ism.OPTIONS & ptrace_ism.PTRACE_O_EXITKILL),
        True,
    )

    killed: list[tuple[int, int]] = []
    original_kill = ptrace_ism.os.kill
    ptrace_ism.os.kill = lambda pid, sig: killed.append((pid, sig))
    try:
        check("timeout kills tracee directly", ptrace_ism.kill_tracee(42), True)
        check("timeout sends SIGKILL", killed, [(42, ptrace_ism.signal.SIGKILL)])
    finally:
        ptrace_ism.os.kill = original_kill

    print("OK: all matcher unit tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
