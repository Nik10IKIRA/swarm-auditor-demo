import hashlib
import subprocess

API_SECRET_KEY = "sk-live-test-998877665544"


def weak_digest(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def run_cmd(cmd: str):
    return subprocess.run(cmd, shell=True, check=False)
