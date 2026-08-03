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
import contextlib
import importlib.machinery
import importlib.util
import io
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


def check_forced_trace_uses_stderr() -> None:
    """A denied child must not pollute the wrapped command's stdout."""
    saved_debug = os.environ.pop("PTRACE_ISM_DEBUG", None)
    saved_trace_file = os.environ.pop("PTRACE_ISM_TRACE_FILE", None)
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            ptrace_ism.Tracer().line("denied", force=True)
        check("forced trace stdout", stdout.getvalue(), "")
        check("forced trace stderr", stderr.getvalue(), "denied\n")
    finally:
        if saved_debug is not None:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is not None:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file


def check_allowed_exec_skips_trace_formatting() -> None:
    """The silent allow path must not build an argv trace line."""
    saved_trace = ptrace_ism.trace
    saved_decide = ptrace_ism.decide
    saved_exec_line = ptrace_ism._exec_line
    saved_debug = os.environ.pop("PTRACE_ISM_DEBUG", None)
    saved_trace_file = os.environ.pop("PTRACE_ISM_TRACE_FILE", None)

    def unexpected_trace_formatting(*_args: object) -> str:
        raise AssertionError("formatted a silent allow event")

    ptrace_ism.trace = ptrace_ism.Tracer()
    ptrace_ism.decide = lambda _: "allow"
    ptrace_ism._exec_line = unexpected_trace_formatting
    try:
        state = ptrace_ism.State()
        check(
            "silent allow skips trace formatting",
            ptrace_ism._apply_policy(state, 1, event(["echo", "x"])),
            True,
        )
    finally:
        ptrace_ism.trace = saved_trace
        ptrace_ism.decide = saved_decide
        ptrace_ism._exec_line = saved_exec_line
        if saved_debug is not None:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is not None:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file


def check_activation_modes() -> None:
    """ptrace is active only for policy enforcement or requested observation."""
    saved_config = os.environ.get("PTRACE_ISM_CONFIG")
    saved_debug = os.environ.pop("PTRACE_ISM_DEBUG", None)
    saved_trace_file = os.environ.pop("PTRACE_ISM_TRACE_FILE", None)
    fd, config_path = tempfile.mkstemp(
        prefix="ptrace-ism-activation-", suffix=".json", dir=str(ROOT)
    )
    os.close(fd)
    missing_path = f"{config_path}.missing"
    try:
        os.environ["PTRACE_ISM_CONFIG"] = missing_path
        reset_config()
        check("missing config does not activate ptrace", ptrace_ism._should_trace(), False)

        os.environ["PTRACE_ISM_CONFIG"] = config_path
        reset_config()
        check("empty config does not activate ptrace", ptrace_ism._should_trace(), False)

        with open(config_path, "w", encoding="utf-8") as stream:
            json.dump({"git": [[["push"]]]}, stream)
        reset_config()
        check("deny config activates ptrace", ptrace_ism._should_trace(), True)

        with open(config_path, "w", encoding="utf-8") as stream:
            json.dump({"git": [[["status"], "allow"]]}, stream)
        reset_config()
        check("allow-only config does not activate ptrace", ptrace_ism._should_trace(), False)

        os.environ["PTRACE_ISM_CONFIG"] = missing_path
        os.environ["PTRACE_ISM_DEBUG"] = "1"
        reset_config()
        check("debug activates ptrace", ptrace_ism._should_trace(), True)

        os.environ.pop("PTRACE_ISM_DEBUG", None)
        os.environ["PTRACE_ISM_TRACE_FILE"] = f"{config_path}.trace"
        reset_config()
        check("trace file activates ptrace", ptrace_ism._should_trace(), True)
    finally:
        os.unlink(config_path)
        if saved_config is None:
            os.environ.pop("PTRACE_ISM_CONFIG", None)
        else:
            os.environ["PTRACE_ISM_CONFIG"] = saved_config
        if saved_debug is not None:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is not None:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file
        else:
            os.environ.pop("PTRACE_ISM_TRACE_FILE", None)


def check_default_mode_execs_directly() -> None:
    """The default mode reaches execvp without creating a tracer state."""
    saved_config = os.environ.get("PTRACE_ISM_CONFIG")
    saved_debug = os.environ.pop("PTRACE_ISM_DEBUG", None)
    saved_trace_file = os.environ.pop("PTRACE_ISM_TRACE_FILE", None)
    saved_execvp = ptrace_ism.os.execvp
    saved_launch = ptrace_ism.launch
    calls: list[tuple[str, list[str]]] = []

    def direct_exec(command: str, argv: list[str]) -> None:
        calls.append((command, argv))

    def unexpected_launch(*_args: object) -> None:
        raise AssertionError("default mode started ptrace")

    os.environ["PTRACE_ISM_CONFIG"] = str(ROOT / "no-such-ptrace-ism-config.json")
    reset_config()
    ptrace_ism.os.execvp = direct_exec
    ptrace_ism.launch = unexpected_launch
    try:
        check("default mode direct exec exit", ptrace_ism.main(["ptrace-ism", "echo", "x"]), 127)
        check("default mode direct exec argv", calls, [("echo", ["echo", "x"])])
    finally:
        ptrace_ism.os.execvp = saved_execvp
        ptrace_ism.launch = saved_launch
        if saved_config is None:
            os.environ.pop("PTRACE_ISM_CONFIG", None)
        else:
            os.environ["PTRACE_ISM_CONFIG"] = saved_config
        if saved_debug is not None:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is not None:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file


def check_trace_file_routing() -> None:
    """Trace-only runs write events and summary to the file, not the terminal."""
    saved_trace = ptrace_ism.trace
    saved_debug = os.environ.pop("PTRACE_ISM_DEBUG", None)
    saved_trace_file = os.environ.get("PTRACE_ISM_TRACE_FILE")
    fd, trace_path = tempfile.mkstemp(
        prefix="ptrace-ism-trace-", suffix=".log", dir=str(ROOT)
    )
    os.close(fd)
    os.environ["PTRACE_ISM_TRACE_FILE"] = trace_path
    stdout = io.StringIO()
    stderr = io.StringIO()
    state = ptrace_ism.State()
    state.root_exit_code = 0
    try:
        ptrace_ism.trace = ptrace_ism.Tracer()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            ptrace_ism.trace.line("allowed event")
            ptrace_ism.trace.line("denied event", force=True)
            ptrace_ism.print_summary(state)
        content = Path(trace_path).read_text(encoding="utf-8")
        check("trace file keeps allowed event", "allowed event" in content, True)
        check("trace file keeps deny event", "denied event" in content, True)
        check("trace file keeps summary", "[ptrace-ism] summary" in content, True)
        check("trace file keeps terminal quiet except deny", stdout.getvalue(), "")
        check("trace file keeps deny visible", stderr.getvalue(), "denied event\n")
    finally:
        ptrace_ism.trace = saved_trace
        os.unlink(trace_path)
        if saved_debug is not None:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is None:
            os.environ.pop("PTRACE_ISM_TRACE_FILE", None)
        else:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file


def check_debug_and_trace_file_routing() -> None:
    """Debug remains interactive when trace-file recording is also enabled."""
    saved_trace = ptrace_ism.trace
    saved_debug = os.environ.get("PTRACE_ISM_DEBUG")
    saved_trace_file = os.environ.get("PTRACE_ISM_TRACE_FILE")
    fd, trace_path = tempfile.mkstemp(
        prefix="ptrace-ism-debug-trace-", suffix=".log", dir=str(ROOT)
    )
    os.close(fd)
    os.environ["PTRACE_ISM_DEBUG"] = "1"
    os.environ["PTRACE_ISM_TRACE_FILE"] = trace_path
    stderr = io.StringIO()
    try:
        ptrace_ism.trace = ptrace_ism.Tracer()
        with contextlib.redirect_stderr(stderr):
            ptrace_ism.trace.line("debug event")
        content = Path(trace_path).read_text(encoding="utf-8")
        check("debug plus trace records event", "debug event" in content, True)
        check("debug plus trace shows event", stderr.getvalue(), "debug event\n")
    finally:
        ptrace_ism.trace = saved_trace
        os.unlink(trace_path)
        if saved_debug is None:
            os.environ.pop("PTRACE_ISM_DEBUG", None)
        else:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is None:
            os.environ.pop("PTRACE_ISM_TRACE_FILE", None)
        else:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file


def check_mode_matrix() -> None:
    """Cover every policy/debug/trace-file activation combination."""
    saved_trace = ptrace_ism.trace
    saved_config = os.environ.get("PTRACE_ISM_CONFIG")
    saved_debug = os.environ.get("PTRACE_ISM_DEBUG")
    saved_trace_file = os.environ.get("PTRACE_ISM_TRACE_FILE")
    fd, config_path = tempfile.mkstemp(
        prefix="ptrace-ism-mode-config-", suffix=".json", dir=str(ROOT)
    )
    os.close(fd)
    trace_paths: list[str] = []
    try:
        for policy, debug, trace_file in (
            (False, False, False),
            (True, False, False),
            (False, True, False),
            (False, False, True),
            (True, True, False),
            (True, False, True),
            (False, True, True),
            (True, True, True),
        ):
            name = f"policy={policy} debug={debug} trace_file={trace_file}"
            with open(config_path, "w", encoding="utf-8") as stream:
                json.dump({"git": [[["push"]]]} if policy else {}, stream)
            os.environ["PTRACE_ISM_CONFIG"] = config_path
            if debug:
                os.environ["PTRACE_ISM_DEBUG"] = "1"
            else:
                os.environ.pop("PTRACE_ISM_DEBUG", None)

            trace_path = f"{config_path}.{policy}-{debug}-{trace_file}.log"
            if trace_file:
                trace_paths.append(trace_path)
                os.environ["PTRACE_ISM_TRACE_FILE"] = trace_path
            else:
                os.environ.pop("PTRACE_ISM_TRACE_FILE", None)

            reset_config()
            active = policy or debug or trace_file
            check(f"{name} activates ptrace", ptrace_ism._should_trace(), active)
            if not active:
                continue

            ptrace_ism.trace = ptrace_ism.Tracer()
            state = ptrace_ism.State()
            state.root_exit_code = 0
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                ptrace_ism.trace.line("allowed event")
                ptrace_ism.trace.line("denied event", force=True)
                ptrace_ism.print_summary(state)
            terminal = stderr.getvalue()
            check(f"{name} shows allowed events only in debug", "allowed event" in terminal, debug)
            check(f"{name} keeps deny visible", "denied event" in terminal, True)
            check(f"{name} shows summary without trace file or in debug", "[ptrace-ism] summary" in terminal, not trace_file or debug)
            if trace_file:
                content = Path(trace_path).read_text(encoding="utf-8")
                check(f"{name} records allowed event", "allowed event" in content, True)
                check(f"{name} records deny event", "denied event" in content, True)
                check(f"{name} records summary", "[ptrace-ism] summary" in content, True)
                os.unlink(trace_path)
                trace_paths.remove(trace_path)
    finally:
        ptrace_ism.trace = saved_trace
        for trace_path in trace_paths:
            try:
                os.unlink(trace_path)
            except FileNotFoundError:
                pass
        os.unlink(config_path)
        reset_config()
        if saved_config is None:
            os.environ.pop("PTRACE_ISM_CONFIG", None)
        else:
            os.environ["PTRACE_ISM_CONFIG"] = saved_config
        if saved_debug is None:
            os.environ.pop("PTRACE_ISM_DEBUG", None)
        else:
            os.environ["PTRACE_ISM_DEBUG"] = saved_debug
        if saved_trace_file is None:
            os.environ.pop("PTRACE_ISM_TRACE_FILE", None)
        else:
            os.environ["PTRACE_ISM_TRACE_FILE"] = saved_trace_file


def main() -> int:
    check_forced_trace_uses_stderr()
    check_allowed_exec_skips_trace_formatting()
    check_activation_modes()
    check_default_mode_execs_directly()
    check_trace_file_routing()
    check_debug_and_trace_file_routing()
    check_mode_matrix()

    # Custom config: deny argument patterns of the named application.
    cfg = write_config(
        {"git": [[["push"]], [["reset", "--hard"]], [["clean"]]]}
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
    cfg_application = write_config({"rm": []})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_application
    try:
        check("deny rm without arguments", decide_argv(["rm"]), "deny")
        check("deny rm with arguments", decide_argv(["rm", "-rf", "tmp"]), "deny")
    finally:
        os.unlink(cfg_application)

    # A universal deny may have more-specific allow exceptions. The longest
    # matching pattern wins; rule order does not participate in the decision.
    cfg_exceptions = write_config(
        {
            "git": [
                [],
                [["status"], "allow"],
                [["push"]],
                [["push", "--dry-run"], "allow"],
            ]
        }
    )
    os.environ["PTRACE_ISM_CONFIG"] = cfg_exceptions
    try:
        check("universal deny blocks git pull", decide_argv(["git", "pull"]), "deny")
        check("specific allow permits git status", decide_argv(["git", "status"]), "allow")
        check("default action denies git push", decide_argv(["git", "push"]), "deny")
        check(
            "longer allow overrides push deny",
            decide_argv(["git", "push", "--dry-run"]),
            "allow",
        )
    finally:
        os.unlink(cfg_exceptions)

    # Equal-length matching patterns with different actions are ambiguous.
    cfg_ambiguous = write_config(
        {"git": [[["push"], "allow"], [["push"], "deny"]]}
    )
    os.environ["PTRACE_ISM_CONFIG"] = cfg_ambiguous
    try:
        expect_refused("ambiguous matching actions refuse to run", ["git", "push"])
    finally:
        os.unlink(cfg_ambiguous)

    # The universal deny has exactly one canonical spelling: application: [].
    cfg_duplicate_universal = write_config({"git": [[]]})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_duplicate_universal
    try:
        expect_refused("duplicate universal syntax refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg_duplicate_universal)

    cfg_non_array_pattern = write_config({"git": [["push"]]})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_non_array_pattern
    try:
        expect_refused("non-array pattern refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg_non_array_pattern)

    cfg_empty_allow_pattern = write_config({"git": [[[], "allow"]]})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_empty_allow_pattern
    try:
        expect_refused("empty allow pattern refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg_empty_allow_pattern)

    cfg_bad_action = write_config({"git": [[["push"], "permit"]]})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_bad_action
    try:
        expect_refused("unknown action refuses to run", ["git", "push"])
    finally:
        os.unlink(cfg_bad_action)

    # Empty config -> no rules -> allow all.
    cfg_empty = write_config({})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_empty
    try:
        check(
            "allow git push (empty config)",
            decide_argv(["git", "push"]),
            "allow",
        )
        check(
            "allow git pull (empty config)",
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

    # A malformed application rule list must not silently disable the policy.
    cfg_bad_rules = write_config({"git": "push"})
    os.environ["PTRACE_ISM_CONFIG"] = cfg_bad_rules
    try:
        expect_refused("non-list rules refuse to run", ["git", "push"])
    finally:
        os.unlink(cfg_bad_rules)

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
