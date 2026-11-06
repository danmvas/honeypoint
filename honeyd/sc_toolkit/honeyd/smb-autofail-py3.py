#!/usr/bin/env python3
"""
smb-autofail-py3.py - Honeyd's stock SMB service script, ported to Python 3.

SOURCE: scripts/misc/smb-autofail.py from DataSoft/Honeyd. This is the only SMB
script Honeyd ships, and Honeyd ships none for RDP.

ONLY the Python 2 -> 3 I/O idioms were changed. The protocol behaviour is
Honeyd's, not ours, and must stay that way for the baseline to be fair:
  * sys.stdin.read(n)  -> sys.stdin.buffer.read(n)      (bytes, not str)
  * "\\x.." literals    -> b"\\x.." literals
  * ord(buf[0])        -> buf[0]                        (already int in py3)
  * chr(n)             -> bytes([n])                    (byte building)
  * time_zone / 256    -> time_zone // 256              (integer division)
  * config strings are encoded to bytes where concatenated into a response

Behaviour preserved, and worth noting when reading the result:
  * only SMB commands 0x72, 0x73, 0x75 and 0x71 are answered; anything else gets
    SendError with command byte 0x72
  * Tree Connect answers NT status 0xC0000022 (STATUS_ACCESS_DENIED)
"""
import sys

native_os = ""
primary_domain = ""
time_zone = 0
lan_manager = ""


def rd(n):
    return sys.stdin.buffer.read(n)


def wr(b):
    sys.stdout.buffer.write(b)
    sys.stdout.buffer.flush()


def GetRequest():
    rd(4)                                   # NetBIOS Session Service header
    if rd(4) != b"\xffSMB":
        return False
    smb_command = rd(1)
    rd(4)                                   # NT status
    rd(1)                                   # Flags 1
    rd(2)                                   # Flags 2
    rd(2)                                   # PID high
    rd(8)                                   # Signature
    rd(2)                                   # Reserved
    rd(2)                                   # Tree ID
    pid = rd(2)
    rd(2)                                   # User ID
    mid = rd(2)

    if smb_command == b"\x72":
        return HandleNegotiateProtocolRequest(pid, mid)
    if smb_command == b"\x73":
        return HandleSessionSetupRequest(pid, mid)
    if smb_command == b"\x75":
        return HandleTreeConnectRequest(pid, mid)
    if smb_command == b"\x71":
        return HandleDisconnectRequest(pid, mid)

    SendError(b"\x72", b"\x00\x00\x00\x00", pid, mid)
    return True


def _hdr(cmd, status, pid, mid, flags2=b"\xc8\x41"):
    r = b"\xffSMB" + cmd + status + b"\x88" + flags2 + b"\x00\x00"
    r += b"\x00" * 8 + b"\x00\x00" + b"\x00\x00" + pid + b"\x00\x00" + mid
    return r


def HandleNegotiateProtocolRequest(pid, mid):
    rd(1)                                   # Word Count
    byte_count = rd(2)
    remaining = byte_count[0] + 256 * byte_count[1]
    dialects = rd(remaining).split(b"\x00")
    chosen = -1
    for i in range(0, len(dialects) - 1):
        if dialects[i][1:] == b"NT LM 0.12":
            chosen = i
            break
    if chosen == -1:
        SendError(b"\x72", b"\x00\x00\x00\x00", pid, mid)
        return True

    r = _hdr(b"\x72", b"\x00\x00\x00\x00", pid, mid)
    r += b"\x11" + bytes([chosen]) + b"\x00" + b"\x08"
    r += b"\x32\x00" + b"\x01\x00" + b"\x04\x41\x00\x00"
    r += b"\x00\x00\x01\x00" + b"\x00\x00\x00\x00"
    r += b"\xf9\xf3\x01\x00"
    r += b"\xa9\xbb\x01\x95\x73\x56\xce\x01"
    r += bytes([time_zone % 256]) + bytes([time_zone // 256]) + b"\x00"
    dom = primary_domain.encode()
    size = len(dom) + 1
    r += bytes([size % 256]) + bytes([size // 256]) + dom + b"\x00"
    wr(b"\x00\x00\x00" + bytes([len(r)]) + r)
    return True


def HandleSessionSetupRequest(pid, mid):
    wc = rd(1)
    rd(wc[0] * 2)
    bc = rd(2)
    rd(bc[0] + 256 * bc[1])

    r = _hdr(b"\x73", b"\x00\x00\x00\x00", pid, mid)
    r += b"\x03" + b"\xff" + b"\x00" + b"\xc7\x00" + b"\x00\x00"
    nos, lanman, dom = native_os.encode(), lan_manager.encode(), primary_domain.encode()
    size = len(nos) + len(lanman) + len(dom) + 3
    r += bytes([size % 256]) + bytes([size // 256])
    r += nos + b"\x00" + lanman + b"\x00" + dom + b"\x00"
    wr(b"\x00\x00\x00" + bytes([len(r)]) + r)
    return True


def HandleTreeConnectRequest(pid, mid):
    wc = rd(1)
    rd(wc[0] * 2)
    bc = rd(2)
    rd(bc[0] + 256 * bc[1])
    # STATUS_ACCESS_DENIED - this is the stock script's behaviour
    r = _hdr(b"\x75", b"\x22\x00\x00\xc0", pid, mid) + b"\x00\x00\x00"
    wr(b"\x00\x00\x00" + bytes([len(r)]) + r)
    return True


def HandleDisconnectRequest(pid, mid):
    wc = rd(1)
    rd(wc[0] * 2)
    bc = rd(2)
    rd(bc[0] + 256 * bc[1])
    r = _hdr(b"\x71", b"\x00\x00\x00\x00", pid, mid, flags2=b"\xc8\x01")
    r += b"\x00\x00\x00"
    wr(b"\x00\x00\x00" + bytes([len(r)]) + r)
    return True


def SendError(error_code, status, pid, mid):
    e = b"\xffSMB" + error_code + status + b"\x88" + b"\xc8\x41" + b"\x00\x00"
    e += b"\x00" * 8 + b"\x00\x00\x00\x00" + b"\x00\x00" + pid + b"\x00\x00" + mid
    e += b"\x00\x00\x00"
    wr(e)
    return True


if len(sys.argv) > 2:
    for line in open(sys.argv[2]):
        k, _, v = line.partition(" ")
        v = v.rstrip()
        if k == "NATIVE_OS":
            native_os = v
        elif k == "PRIMARY_DOMAIN":
            primary_domain = v
        elif k == "TIME_ZONE":
            time_zone = int(v)
        elif k == "LAN_MANAGER":
            lan_manager = v

keep_going = True
while keep_going:
    keep_going = GetRequest()
