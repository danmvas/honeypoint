#!/usr/bin/env python3
"""
probe_smb.py - drive the MS17-010 reconnaissance procedure and record it.

A hand-written stand-in for the Metasploit/Nmap SMB check, used to smoke-test a
target and the observer without installing either. It walks the five declared
stages and writes a pcap of the exchange.

    python3 probe_smb.py --host 127.0.0.1 --port 445 --pcap run.pcap [--stop-at 4]

--stop-at 4 reproduces a scanner that halts once it holds its verdict; the
default walks all five, like a tool that continues past it.

This is NOT a substitute for running the real scanners. Use it to check that a
target and the observer agree before committing to a full run matrix.
"""
import argparse, socket, struct, sys, time

NB = lambda p: struct.pack(">B", 0) + len(p).to_bytes(3, "big")


def smb_hdr(cmd, tid=0, uid=0):
    h = b"\xffSMB" + struct.pack("<B", cmd) + struct.pack("<I", 0)
    h += struct.pack("<B", 0x18) + struct.pack("<H", 0xC853)
    h += b"\x00" * 2 + b"\x00" * 8 + b"\x00" * 2
    h += struct.pack("<H", tid) + struct.pack("<H", 0xFEFF)
    h += struct.pack("<H", uid) + struct.pack("<H", 1)
    return h


def req_negotiate():
    d = b"".join(b"\x02" + x + b"\x00" for x in
                 [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"NT LM 0.12"])
    p = smb_hdr(0x72) + struct.pack("<B", 0) + struct.pack("<H", len(d)) + d
    return NB(p) + p


def req_session_setup():
    w = struct.pack("<BB", 0xFF, 0) + struct.pack("<H", 0)
    w += struct.pack("<H", 4356) + struct.pack("<H", 1)
    w += struct.pack("<H", 0) + struct.pack("<I", 0)
    w += struct.pack("<H", 1) + struct.pack("<H", 0)
    w += struct.pack("<I", 0) + struct.pack("<I", 0x80000000)
    s = b"\x00" + b"Unix\x00" + b"Samba\x00" + b"WORKGROUP\x00"
    p = smb_hdr(0x73) + struct.pack("<B", 13) + w + struct.pack("<H", len(s)) + s
    return NB(p) + p


def req_tree_connect(uid, host):
    path = f"\\\\{host}\\IPC$".encode("utf-16-le") + b"\x00\x00"
    w = struct.pack("<BB", 0xFF, 0) + struct.pack("<H", 0)
    w += struct.pack("<H", 0) + struct.pack("<H", 1)
    pay = b"\x00" + path + b"?????\x00"
    p = smb_hdr(0x75, uid=uid) + struct.pack("<B", 4) + w
    p += struct.pack("<H", len(pay)) + pay
    return NB(p) + p


def req_trans_peek(uid, tid, fid=0x4000):
    setup = struct.pack("<HH", 0x0023, fid)
    name = b"\\PIPE\\\x00"
    w = struct.pack("<HH", 0, 0) + struct.pack("<HH", 1024, 0)
    w += struct.pack("<BB", 0, 0) + struct.pack("<H", 0)
    w += struct.pack("<I", 0) + struct.pack("<H", 0)
    w += struct.pack("<HH", 0, 0) + struct.pack("<HH", 0, 0)
    w += struct.pack("<BB", 2, 0)
    p = smb_hdr(0x25, tid=tid, uid=uid) + struct.pack("<B", 16) + w + setup
    p += struct.pack("<H", len(name)) + name
    return NB(p) + p


def write_pcap(path, wire, cli_ip, srv_ip, sport, dport):
    out = bytearray(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    seq = {"c": 1, "s": 1}
    for ts, who, pl in wire:
        src, dst = (cli_ip, srv_ip) if who == "c" else (srv_ip, cli_ip)
        sp, dp = (sport, dport) if who == "c" else (dport, sport)
        tcp = struct.pack(">HHIIBBHHH", sp, dp, seq[who], 0, 5 << 4, 0x18, 8192, 0, 0)
        seq[who] += len(pl)
        body = tcp + pl
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(body), 0, 0, 64, 6, 0)
        ip += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
        frame = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + body
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame))
        out += frame
    with open(path, "wb") as fh:
        fh.write(bytes(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=445)
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--stop-at", type=int, default=5, choices=[1, 2, 3, 4, 5])
    a = ap.parse_args()

    wire = []
    s = socket.create_connection((a.host, a.port), timeout=5)

    def xchg(req):
        wire.append((time.time(), "c", req))
        s.sendall(req)
        time.sleep(0.05)
        try:
            r = s.recv(8192)
        except socket.timeout:
            r = b""
        if r:
            wire.append((time.time(), "s", r))
        return r

    xchg(req_negotiate())
    uid, tid = 100, 2048
    if a.stop_at >= 2:
        r = xchg(req_session_setup())
        if len(r) >= 34:
            uid = struct.unpack("<H", r[4 + 28:4 + 30])[0]
    if a.stop_at >= 3:
        r = xchg(req_tree_connect(uid, a.host))
        if len(r) >= 30:
            tid = struct.unpack("<H", r[4 + 24:4 + 26])[0]
    if a.stop_at >= 4:
        xchg(req_trans_peek(uid, tid))
    if a.stop_at >= 5:
        xchg(req_trans_peek(uid, tid))
    s.close()

    if a.pcap:
        write_pcap(a.pcap, wire, "10.0.0.2", "10.0.0.1", 50000, a.port)
        print(f"wrote {a.pcap} ({len(wire)} records)")
    else:
        for ts, who, pl in wire:
            print(who, len(pl), pl[:16].hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
