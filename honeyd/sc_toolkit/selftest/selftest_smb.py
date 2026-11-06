#!/usr/bin/env python3
"""Smoke test: drive the EternalBlue driver, capture the exchange, score it."""
import os, struct, socket, threading, time, json, sys, glob, tempfile

LOGDIR = tempfile.mkdtemp(prefix="sc_selftest_")
os.environ["STAGED_LOG_DIR"] = LOGDIR
sys.path.insert(0, "hp")

from framework.tracker import SCTracker
from drivers.eternalblue import EternalBlueDriver

PORT = 14455
NB = lambda p: struct.pack(">B", 0) + len(p).to_bytes(3, "big")

def smb_hdr(cmd, tid=0, uid=0):
    h = b"\xffSMB" + struct.pack("<B", cmd) + struct.pack("<I", 0)
    h += struct.pack("<B", 0x18) + struct.pack("<H", 0xC853)
    h += b"\x00" * 2 + b"\x00" * 8 + b"\x00" * 2
    h += struct.pack("<H", tid) + struct.pack("<H", 0xFEFF)
    h += struct.pack("<H", uid) + struct.pack("<H", 1)
    return h

def req_negotiate():
    dialects = b"".join(b"\x02" + d + b"\x00" for d in
                        [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"NT LM 0.12"])
    body = struct.pack("<B", 0) + struct.pack("<H", len(dialects)) + dialects
    p = smb_hdr(0x72) + body
    return NB(p) + p

def req_session_setup():
    words = struct.pack("<BB", 0xFF, 0) + struct.pack("<H", 0)
    words += struct.pack("<H", 4356) + struct.pack("<H", 1)
    words += struct.pack("<H", 0) + struct.pack("<I", 0)
    words += struct.pack("<H", 1) + struct.pack("<H", 0)     # oem, uni pw len
    words += struct.pack("<I", 0) + struct.pack("<I", 0x80000000)
    assert len(words) == 26, len(words)
    strings = b"\x00" + b"Unix\x00" + b"Samba\x00" + b"WORKGROUP\x00"
    body = struct.pack("<B", 13) + words + struct.pack("<H", len(strings)) + strings
    p = smb_hdr(0x73) + body
    return NB(p) + p

def req_tree_connect(uid):
    path = "\\\\127.0.0.1\\IPC$".encode("utf-16-le") + b"\x00\x00"
    words = struct.pack("<BB", 0xFF, 0) + struct.pack("<H", 0)
    words += struct.pack("<H", 0) + struct.pack("<H", 1)      # flags, pw len = 1
    assert len(words) == 8
    payload = b"\x00" + path + b"?????\x00"
    body = struct.pack("<B", 4) + words + struct.pack("<H", len(payload)) + payload
    p = smb_hdr(0x75, uid=uid) + body
    return NB(p) + p

def req_trans_peek(uid, tid, fid=0x4000):
    setup = struct.pack("<HH", 0x0023, fid)                  # PeekNamedPipe, FID
    name = b"\\PIPE\\\x00"
    words = struct.pack("<HH", 0, 0) + struct.pack("<HH", 1024, 0)
    words += struct.pack("<BB", 0, 0) + struct.pack("<H", 0)
    words += struct.pack("<I", 0) + struct.pack("<H", 0)
    words += struct.pack("<HH", 0, 0) + struct.pack("<HH", 0, 0)
    words += struct.pack("<BB", 2, 0)
    assert len(words) == 28, len(words)
    body = struct.pack("<B", 16) + words + setup
    body += struct.pack("<H", len(name)) + name
    p = smb_hdr(0x25, tid=tid, uid=uid) + body
    return NB(p) + p

# ---- run the driver
driver = EternalBlueDriver()
meta = driver.get_metadata()
tracker = SCTracker.from_metadata(meta)
threading.Thread(target=driver.start, args=(PORT, tracker), daemon=True).start()
time.sleep(1.0)

# ---- drive it, recording both directions
wire = []
s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
def xchg(req):
    wire.append((time.time(), "c", req)); s.sendall(req)
    try:
        rsp = s.recv(8192)
    except socket.timeout:
        rsp = b""
    if rsp: wire.append((time.time(), "s", rsp))
    return rsp

r1 = xchg(req_negotiate())
r2 = xchg(req_session_setup())
uid = struct.unpack("<H", r2[4+28:4+30])[0] if len(r2) >= 34 else 100
r3 = xchg(req_tree_connect(uid))
tid = struct.unpack("<H", r3[4+24:4+26])[0] if len(r3) >= 30 else 2048
r4 = xchg(req_trans_peek(uid, tid))
r5 = xchg(req_trans_peek(uid, tid))      # second transaction -> stage 5
s.close()
time.sleep(0.8)

# ---- synthesize a pcap from the recorded exchange
def write_pcap(path, wire, sport=50000, dport=PORT):
    out = bytearray(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    seq = {"c": 1, "s": 1}
    for ts, who, payload in wire:
        src, dst = ("10.0.0.2", "10.0.0.1") if who == "c" else ("10.0.0.1", "10.0.0.2")
        sp, dp = (sport, dport) if who == "c" else (dport, sport)
        tcp = struct.pack(">HHIIBBHHH", sp, dp, seq[who], 0, 5 << 4, 0x18, 8192, 0, 0)
        seq[who] += len(payload)
        ip_body = tcp + payload
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(ip_body), 0, 0, 64, 6, 0)
        ip += bytes(int(x) for x in src.split(".")) + bytes(int(x) for x in dst.split("."))
        frame = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + ip_body
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame))
        out += frame
    open(path, "wb").write(bytes(out))

write_pcap("out/selftest.pcap", wire)

# ---- SC_int from the driver's own records
files = sorted(glob.glob(os.path.join(LOGDIR, "sc_*.json")))
sc_int = json.load(open(files[-1])) if files else None
print("responses:", [len(x) for x in (r1, r2, r3, r4, r5)])
print("SC_int    :", sc_int["completed_stages"], "/", sc_int["total_stages"],
      sorted(e["stage_number"] for e in sc_int["events"]))
print("records   :", len(wire))
