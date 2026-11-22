import os
import shlex
import hashlib
import subprocess
API_SECRET_KEY = os.getenv('API_SECRET_KEY', '')

def weak_digest(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def run_cmd(cmd: str):
    return subprocess.run(shlex.split(cmd), shell=False, check=False)
