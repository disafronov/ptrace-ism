"""Storm/smoke tests: run the ptrace-ism wrapper around a command under a
parallel fork/exec storm (pytest -n 16).

The 40 files in tests/test_storm_*.py are intentionally byte-identical so
pytest-xdist distributes them across workers; together they fire 80 ptrace-ism
invocations. Each test proves the tool actually ran as the wrapper by asserting
a debug-enabled `[ptrace-ism] summary` stderr line.
"""
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "ptrace-ism")


def _run(cmd):
    """Run `cmd` through the ptrace-ism wrapper; return the CompletedProcess.

    Deterministic, host-independent env: the config points at a definitely
    nonexistent path (missing config -> allow all); PTRACE_ISM_TIMEOUT and
    PTRACE_ISM_DEBUG=1 activates tracing for this storm.
    """
    env = os.environ.copy()
    env["PTRACE_ISM_CONFIG"] = os.path.join(
        ROOT, "no-such-ptrace-ism-config.json"
    )
    env["PTRACE_ISM_DEBUG"] = "1"
    return subprocess.run(
        [SCRIPT] + cmd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_uname():
    proc = _run(["/usr/bin/uname", "-p"])
    assert proc.returncode == 0
    assert "[ptrace-ism] summary" in proc.stderr


def test_spawn():
    proc = _run(["/bin/echo", "x"])
    assert proc.returncode == 0
    assert "[ptrace-ism] summary" in proc.stderr
