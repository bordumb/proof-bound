from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 6:
        raise ValueError("expected mode, input, output, attack path, and port")
    mode, input_path, output_path, attack_path, port_text = sys.argv[1:]
    output = Path(output_path)
    attack = Path(attack_path)

    if mode == "positive":
        value = Path(input_path).read_bytes().strip()
        environment = os.environ["PB_REGISTERED_VALUE"].encode("utf-8")
        output.write_bytes(value + b"|" + environment + b"\n")
        return 0
    if mode == "read-undeclared":
        output.write_bytes(attack.read_bytes())
        return 0
    if mode == "env-undeclared":
        output.write_bytes(os.environ["PB_UNDECLARED_VALUE"].encode("utf-8"))
        return 0
    if mode == "exec-unregistered":
        subprocess.run(["/usr/bin/true"], check=True)
        output.write_bytes(b"child-executed\n")
        return 0
    if mode == "network":
        with socket.create_connection(("127.0.0.1", int(port_text)), timeout=2):
            output.write_bytes(b"network-observed\n")
        return 0
    if mode in {"write-reviewed", "write-escape"}:
        attack.write_bytes(b"unauthorized-write\n")
        return 0
    raise ValueError(f"unknown mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
