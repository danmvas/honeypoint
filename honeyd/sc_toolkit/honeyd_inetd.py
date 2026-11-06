#!/usr/bin/env python3
"""
honeyd_inetd.py - run a Honeyd service script the way Honeyd runs it.

Honeyd's extension point is a program whose stdin and stdout are connected to
the TCP connection ("add <template> tcp port 445 \"scripts/...\""). This wrapper
reproduces that contract so a service script can be developed and measured
without a working Honeyd build.

    sudo python3 honeyd_inetd.py --port 445 -- \
         python3 honeyd/smb-autofail-py3.py x honeyd/smb.conf

What this DOES reproduce: the application-layer contract, i.e. exactly the bytes
the script sees and emits. That is what Stage Coverage measures.

What it does NOT reproduce: Honeyd's own simplified TCP state machine, its
personality engine, and its virtual routing. Those affect how the host
fingerprints, not how far a reconnaissance procedure advances. A figure obtained
through this wrapper is therefore an estimate of the SCRIPT's stage depth under
Honeyd, and must be labelled as such - never reported as "Honeyd" without
confirming it against a real Honeyd deployment.
"""
import argparse, os, socket, subprocess, sys, threading


def serve_one(conn, addr, cmd):
    try:
        proc = subprocess.Popen(cmd, stdin=conn.fileno(), stdout=conn.fileno(),
                                stderr=subprocess.DEVNULL, close_fds=False)
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as exc:                                  # noqa: BLE001
        print(f"[inetd] {addr}: {exc}", file=sys.stderr)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="-- followed by the service script command line")
    a = ap.parse_args()
    cmd = [c for c in a.cmd if c != "--"]
    if not cmd:
        raise SystemExit("give the script command after --")

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port))
    srv.listen(16)
    print(f"[inetd] port {a.port} -> {' '.join(cmd)}", file=sys.stderr)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=serve_one, args=(conn, addr, cmd),
                         daemon=True).start()


if __name__ == "__main__":
    main()
