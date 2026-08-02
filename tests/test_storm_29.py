import subprocess

def test_uname():
    subprocess.run(["/usr/bin/uname", "-p"], stdout=subprocess.DEVNULL, check=True)

def test_spawn():
    subprocess.run(["/bin/echo", "x"], stdout=subprocess.DEVNULL, check=True)
