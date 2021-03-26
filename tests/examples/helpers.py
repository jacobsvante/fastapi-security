import os
import socket
import subprocess
from contextlib import contextmanager
from typing import Dict


def available_port(ip: str = "127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def run_example_app(app_path: str, *, env: Dict[str, str] = None):
    port = available_port()
    proc = subprocess.Popen(
        ["uvicorn", app_path, f"--port={port}"],
        stderr=subprocess.PIPE,
        env={**os.environ, **(env or {})},
    )

    while True:
        if proc.stderr:
            line = proc.stderr.readline()
            if b"Uvicorn running on" in line:
                break
            elif b"Traceback" in line:
                lines = proc.stderr.read()
                proc.terminate()
                raise RuntimeError(lines.decode())
        else:
            break

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
