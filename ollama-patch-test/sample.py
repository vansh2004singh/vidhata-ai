import subprocess

def get_version():
    return subprocess.run(
        "git --version",
        shell=True,
        capture_output=True,
        text=True,
    ).stdout
