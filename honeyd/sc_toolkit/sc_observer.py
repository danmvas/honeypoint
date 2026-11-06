#!/usr/bin/env python3
"""
sc_observer.py - Stage Coverage from a packet capture.

Scores a pcap against the stage list of a reconnaissance attack, without
consulting the target's own logs. This is what lets a third-party decoy that
declares no stages be placed on the same scale as a honeypoint driver.

Standard library only, like the framework itself.

    tcpdump -i <iface> -s0 -w run.pcap 'tcp port 445'
    python3 sc_observer.py --pcap run.pcap --attack eternalblue

A stage is credited only when BOTH the client request and the server response
that constitute the exchange are present. A target that does not sustain an
exchange is therefore not credited for it, which is the whole point of
measuring from the wire rather than from the decoy.

Output is one JSON object per TCP session: the ordered stage trace, |C|, N and
SC. Keep the traces: SC under a revised stage list is recomputable from them
without repeating any run.
"""

import argparse
import json
import struct
import sys
from collections import defaultdict

# ----------------------------------------------------------------- pcap

DLT_NULL, DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2 = 0, 1, 113, 276


def read_pcap(path):
    """Yield (timestamp, ip_payload_bytes) for every IPv4 packet."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise SystemExit("pcap too short")
    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, div = "<", 1_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, div = ">", 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, div = "<", 1_000_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, div = ">", 1_000_000_000
    elif magic[:4] == b"\x0a\x0d\x0d\x0a":
        raise SystemExit("pcapng is not supported; capture with 'tcpdump -w' "
                         "(classic pcap) or convert with editcap -F pcap")
    else:
        raise SystemExit("not a pcap file")
    dlt = struct.unpack(endian + "I", blob[20:24])[0]
    off = 24
    while off + 16 <= len(blob):
        ts_s, ts_f, caplen, _ = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        pkt = blob[off:off + caplen]
        off += caplen
        ip = _strip_link(pkt, dlt)
        if ip:
            yield ts_s + ts_f / div, ip


def _strip_link(pkt, dlt):
    if dlt == DLT_EN10MB:
        if len(pkt) < 14:
            return None
        etype = struct.unpack(">H", pkt[12:14])[0]
        hdr = 14
        while etype in (0x8100, 0x88A8) and len(pkt) >= hdr + 4:   # VLAN tags
            etype = struct.unpack(">H", pkt[hdr + 2:hdr + 4])[0]
            hdr += 4
        return pkt[hdr:] if etype == 0x0800 else None
    if dlt == DLT_NULL:
        if len(pkt) < 4:
            return None
        fam = struct.unpack("<I", pkt[:4])[0]
        if fam not in (2, 0x02000000):
            fam = struct.unpack(">I", pkt[:4])[0]
        return pkt[4:] if fam == 2 else None
    if dlt == DLT_LINUX_SLL:
        if len(pkt) < 16:
            return None
        return pkt[16:] if struct.unpack(">H", pkt[14:16])[0] == 0x0800 else None
    if dlt == DLT_LINUX_SLL2:
        if len(pkt) < 20:
            return None
        return pkt[20:] if struct.unpack(">H", pkt[0:2])[0] == 0x0800 else None
    return None


def tcp_segments(path):
    """Yield (ts, src, sport, dst, dport, seq, flags, payload)."""
    for ts, ip in read_pcap(path):
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6 or len(ip) < ihl + 20:
            continue
        total = struct.unpack(">H", ip[2:4])[0] or len(ip)
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        yield ts, src, sport, dst, dport, seq, flags, tcp[doff:]


# ------------------------------------------------------- reassembly

class Direction:
    """One half of a TCP connection, reassembled in sequence order."""

    def __init__(self):
        self.chunks = {}        # seq -> payload (last write wins: retransmits)
        self.base = None

    def add(self, seq, payload):
        if not payload:
            return
        if self.base is None or _seq_lt(seq, self.base):
            self.base = seq
        self.chunks.setdefault(seq, payload)

    def stream(self):
        """Return (bytes, marks) where marks maps stream offset -> seq order."""
        out, marks, cursor = bytearray(), [], None
        for seq in sorted(self.chunks, key=lambda s: _seq_key(s, self.base)):
            payload = self.chunks[seq]
            if cursor is not None:
                gap = _seq_key(seq, self.base) - cursor
                if gap > 0:
                    out.extend(b"\x00" * min(gap, 1 << 20))   # tolerate loss
                elif gap < 0:
                    payload = payload[-gap:] if -gap < len(payload) else b""
            marks.append((len(out), seq))
            out.extend(payload)
            cursor = _seq_key(seq, self.base) + len(self.chunks[seq])
        return bytes(out), marks


def _seq_key(seq, base):
    return ((seq - base) & 0xFFFFFFFF)


def _seq_lt(a, b):
    return ((a - b) & 0xFFFFFFFF) > 0x7FFFFFFF


def sessions(path, server_port):
    """Group segments into sessions keyed by (client, cport, server, sport)."""
    halves = defaultdict(Direction)
    times = {}
    for ts, src, sport, dst, dport, seq, flags, payload in tcp_segments(path):
        if server_port not in (sport, dport):
            continue
        if dport == server_port:
            key, direction = (src, sport, dst, dport), "c"
        else:
            key, direction = (dst, dport, src, sport), "s"
        halves[(key, direction)].add(seq, payload)
        times.setdefault((key, direction), {})[seq] = ts
        t0, t1 = times.setdefault(("span", key), {}), None
        t0.setdefault("first", ts)
        t0["last"] = ts
    keys = {k for (k, _d) in halves if k != "span"}
    for key in sorted(keys):
        c_bytes, c_marks = halves[(key, "c")].stream()
        s_bytes, s_marks = halves[(key, "s")].stream()
        span = times.get(("span", key), {})
        yield key, (c_bytes, c_marks, times.get((key, "c"), {})), \
                   (s_bytes, s_marks, times.get((key, "s"), {})), span


def _ts_for(offset, marks, seqts):
    best = None
    for off, seq in marks:
        if off <= offset:
            best = seqts.get(seq)
        else:
            break
    return best


# ------------------------------------------------------- record framing

def frame_nbss(stream, marks, seqts):
    """NetBIOS Session Service records: 1 type byte + 3 length bytes."""
    out, i = [], 0
    while i + 4 <= len(stream):
        length = int.from_bytes(stream[i + 1:i + 4], "big")
        if length == 0 or i + 4 + length > len(stream):
            break
        out.append((_ts_for(i, marks, seqts), stream[i:i + 4 + length]))
        i += 4 + length
    return out


def frame_tpkt(stream, marks, seqts):
    """TPKT records: version 3, reserved, 2-byte big-endian length."""
    out, i = [], 0
    while i + 4 <= len(stream):
        if stream[i] != 3:
            break
        length = struct.unpack(">H", stream[i + 2:i + 4])[0]
        if length < 4 or i + length > len(stream):
            break
        out.append((_ts_for(i, marks, seqts), stream[i:i + length]))
        i += length
    return out


# ------------------------------------------------------- SMB dissection

SMB_NEGOTIATE, SMB_SESSION_SETUP, SMB_TREE_CONNECT = 0x72, 0x73, 0x75
SMB_TRANSACTION, SMB_TRANSACTION2, SMB_NT_TRANSACT = 0x25, 0x32, 0xA0
STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205


def smb_fields(rec):
    """Return {command, status} for an SMB1 record, or None."""
    if len(rec) < 4 + 32 or rec[4:8] != b"\xffSMB":
        return None
    return {"command": rec[8], "status": struct.unpack("<I", rec[9:13])[0]}


def smb_trans_subcommand(rec):
    try:
        words_start = 4 + 32 + 1
        word_count = rec[4 + 32]
        if word_count < 14:
            return None
        setup_count = rec[words_start + 26]
        if setup_count < 1:
            return None
        return struct.unpack("<H", rec[words_start + 28:words_start + 30])[0]
    except (IndexError, struct.error):
        return None


def smb_tree_path(rec):
    try:
        body = 4 + 32
        word_count = rec[body]
        words_start = body + 1
        pw_len = struct.unpack("<H", rec[words_start + 6:words_start + 8])[0]
        bc = words_start + word_count * 2
        raw = rec[bc + 2 + pw_len:]
        dn = raw.find(b"\x00\x00")
        if 0 < dn < 100:
            return raw[:dn + 1].decode("utf-16-le", "replace").rstrip("\x00")
        nn = raw.find(b"\x00")
        return raw[:nn].decode("ascii", "replace") if nn > 0 else ""
    except (IndexError, struct.error, UnicodeDecodeError):
        return ""


# ------------------------------------------------------- RDP dissection

def x224_type(rec):
    return rec[5] if len(rec) >= 6 else None


def rdp_neg_response(rec):
    """True if an X.224 Connection Confirm carries an RDP_NEG_RSP (type 0x02)."""
    if len(rec) < 11 or x224_type(rec) != 0xD0:
        return False
    return rec[11] == 0x02 if len(rec) >= 12 else False


def mcs_offset(rec):
    off = 4
    if len(rec) > off + 1 and rec[off] == 0x02 and rec[off + 1] == 0xF0:
        off += 3
    return off


def mcs_type(rec):
    off = mcs_offset(rec)
    return rec[off] if len(rec) > off else None


def mcs_is(rec, kinds):
    t = mcs_type(rec)
    return t is not None and t in kinds


def mcs_channel_join_fields(rec):
    off = mcs_offset(rec)
    try:
        return (struct.unpack(">H", rec[off + 1:off + 3])[0],
                struct.unpack(">H", rec[off + 3:off + 5])[0])
    except (IndexError, struct.error):
        return 0, 0


def mcs_attach_confirm_user(rec):
    off = mcs_offset(rec)
    try:
        return struct.unpack(">H", rec[off + 2:off + 4])[0]
    except (IndexError, struct.error):
        return 0


def mcs_is_connect_initial(rec):
    off = mcs_offset(rec)
    return len(rec) > off + 1 and rec[off] == 0x7F and rec[off + 1] == 0x65


def mcs_is_connect_response(rec):
    off = mcs_offset(rec)
    return len(rec) > off + 1 and rec[off] == 0x7F and rec[off + 1] == 0x66


# ------------------------------------------------------- recognisers
#
# Each recogniser receives the two directions separately as lists of
# (timestamp, record). Stages are decided from the record SET rather than by a
# single ordered pass, because a server response and the client's next request
# can carry indistinguishable timestamps in a capture; an ordered pass would
# then drop a stage that did occur. EPS absorbs that ambiguity.

EPS = 1e-6

ETERNALBLUE_STAGES = {1: "SMB Negotiate", 2: "Session Setup",
                      3: "Tree Connect IPC$", 4: "PeekNamedPipe",
                      5: "Post-verdict Transaction"}

BLUEKEEP_STAGES = {1: "X.224 Connection Request", 2: "Security Negotiation",
                   3: "MCS Connect Initial", 4: "Channel Join",
                   5: "Exploit PDU"}

MS12020_STAGES = {1: "X.224 Connection Request", 2: "Security Negotiation",
                  3: "MCS Connect Initial", 4: "Second Attach User",
                  5: "Cross-User Channel Bind"}


class Trace:
    """Accumulates completed stages in stage order."""

    def __init__(self, names):
        self.names, self.events, self.done = names, {}, set()

    def complete(self, n, t_req, t_rsp=None, **extra):
        if n in self.done:
            return
        self.done.add(n)
        ev = {"stage": n, "name": self.names[n],
              "t_request": t_req, "t_response": t_rsp}
        ev.update(extra)
        self.events[n] = ev

    def result(self):
        return [self.events[n] for n in sorted(self.events)], self.done


def _first(records, pred):
    for ts, rec in records:
        if pred(rec):
            return ts, rec
    return None, None


def _any_after(records, pred, after):
    for ts, rec in records:
        if ts is None or after is None or ts >= after - EPS:
            if pred(rec):
                return ts, rec
    return None, None


def score_eternalblue(cli, srv):
    """EternalBlue / CVE-2017-0144, N = 5."""
    tr = Trace(ETERNALBLUE_STAGES)
    TRANS = (SMB_TRANSACTION, SMB_TRANSACTION2, SMB_NT_TRANSACT)

    def cmd_is(c):
        return lambda rec: (smb_fields(rec) or {}).get("command") == c

    def reply(c, after, status=None):
        def pred(rec):
            f = smb_fields(rec)
            return bool(f) and f["command"] == c and (status is None
                                                      or f["status"] == status)
        return _any_after(srv, pred, after)[0]

    t, _ = _first(cli, cmd_is(SMB_NEGOTIATE))
    if t is not None:
        r = reply(SMB_NEGOTIATE, t)
        if r is not None:
            tr.complete(1, t, r)

    t, _ = _first(cli, cmd_is(SMB_SESSION_SETUP))
    if t is not None:
        r = reply(SMB_SESSION_SETUP, t, status=0)
        if r is not None:
            tr.complete(2, t, r)

    t, _ = _first(cli, lambda rec: cmd_is(SMB_TREE_CONNECT)(rec)
                  and "IPC$" in smb_tree_path(rec).upper())
    if t is not None:
        # The tree connect must SUCCEED: a target that answers IPC$ with
        # ACCESS_DENIED has not let the procedure advance, and the scanner
        # cannot issue the named-pipe probe that follows.
        r = reply(SMB_TREE_CONNECT, t, status=0)
        if r is not None:
            tr.complete(3, t, r)

    # stage 4 is the first PeekNamedPipe; stage 5 is any later transaction,
    # which is what separates a scanner from a tool that continues past the
    # verdict it came for.
    peeks = [(ts, rec) for ts, rec in cli
             if (smb_fields(rec) or {}).get("command") in TRANS
             and smb_trans_subcommand(rec) == 0x0023]
    trans = [(ts, rec) for ts, rec in cli
             if (smb_fields(rec) or {}).get("command") in TRANS]
    if peeks:
        t4 = peeks[0][0]
        # Stage 4 is the verdict-bearing exchange. It counts only when the
        # response carries STATUS_INSUFF_SERVER_RESOURCES, which is the status
        # a vulnerable host returns and the one the scanner reads as
        # confirmation. Any other answer means the deception did not land.
        def verdict(rec):
            f = smb_fields(rec)
            return (bool(f) and f["command"] in TRANS
                    and f["status"] == STATUS_INSUFF_SERVER_RESOURCES)

        t_rsp, _ = _any_after(srv, verdict, t4)
        if t_rsp is not None:
            tr.complete(4, t4, t_rsp, verdict="STATUS_INSUFF_SERVER_RESOURCES")
        later = [ts for ts, _ in trans if ts is not None and t4 is not None
                 and ts > t4 + EPS]
        if later and 4 in tr.done:
            tr.complete(5, later[0], None, note="continued past the verdict")
    return tr.result()


def _rdp_trunk(cli, srv, tr):
    """Stages 1-3, shared by every driver of the RDP-Recon family."""
    t_cr, _ = _first(cli, lambda rec: x224_type(rec) == 0xE0)
    t_cc, cc = _any_after(srv, lambda rec: x224_type(rec) == 0xD0, t_cr)
    if t_cr is not None and cc is not None:
        tr.complete(1, t_cr, t_cc)
        if rdp_neg_response(cc):
            tr.complete(2, t_cr, t_cc)
    t_ci, _ = _first(cli, mcs_is_connect_initial)
    t_cp, cp = _any_after(srv, mcs_is_connect_response, t_ci)
    if t_ci is not None and cp is not None:
        tr.complete(3, t_ci, t_cp)
    return tr


def score_bluekeep(cli, srv):
    """BlueKeep / CVE-2019-0708, N = 5."""
    tr = _rdp_trunk(cli, srv, Trace(BLUEKEEP_STAGES))
    t_join, join = _first(cli, lambda rec: mcs_is(rec, (0x38, 0x3A)))
    t_conf, conf = _any_after(srv, lambda rec: mcs_is(rec, (0x3E,)), t_join)
    if join is not None and conf is not None:
        _, channel = mcs_channel_join_fields(join)
        tr.complete(4, t_join, t_conf, channel_id=channel,
                    ms_t120_attempted=channel in (0, 31))
    t_sd, sd = _first(cli, lambda rec: mcs_is(rec, (0x64, 0x68)))
    if sd is not None and 4 in tr.done:
        tr.complete(5, t_sd, None, payload_bytes=len(sd))
    return tr.result()


def score_ms12_020(cli, srv):
    """MS12-020 / CVE-2012-0002, N = 5."""
    tr = _rdp_trunk(cli, srv, Trace(MS12020_STAGES))
    confirms = [(ts, mcs_attach_confirm_user(rec)) for ts, rec in srv
                if mcs_is(rec, (0x2E,))]
    requests = [ts for ts, rec in cli if mcs_is(rec, (0x28, 0x2A))]
    attached = [u for _ts, u in confirms]
    if len(confirms) >= 2:
        t_req = requests[1] if len(requests) >= 2 else requests[0] if requests else None
        tr.complete(4, t_req, confirms[1][0], attached_user_ids=list(attached))
    if 4 in tr.done:
        for ts, rec in cli:
            if not mcs_is(rec, (0x38, 0x3A)):
                continue
            initiator, channel = mcs_channel_join_fields(rec)
            if initiator in attached and initiator != attached[-1]:
                tr.complete(5, ts, None, initiator=initiator, channel_id=channel)
                break
    return tr.result()


ATTACKS = {
    "eternalblue": {"n": 5, "port": 445, "framer": frame_nbss,
                    "scorer": score_eternalblue, "cve": "CVE-2017-0144"},
    "bluekeep":    {"n": 5, "port": 3389, "framer": frame_tpkt,
                    "scorer": score_bluekeep, "cve": "CVE-2019-0708"},
    "ms12_020":    {"n": 5, "port": 3389, "framer": frame_tpkt,
                    "scorer": score_ms12_020, "cve": "CVE-2012-0002"},
}


def analyse(pcap, attack, port=None, target=None, tool=None):
    spec = ATTACKS[attack]
    port = port or spec["port"]
    results = []
    for key, cli, srv, span in sessions(pcap, port):
        framer = spec["framer"]
        c_recs, s_recs = framer(*cli), framer(*srv)
        trace, done = spec["scorer"](c_recs, s_recs)
        results.append({
            "target": target, "tool": tool, "attack": attack,
            "cve": spec["cve"], "client": f"{key[0]}:{key[1]}",
            "server": f"{key[2]}:{key[3]}",
            "start_time": span.get("first"), "end_time": span.get("last"),
            "total_stages": spec["n"], "completed_stages": len(done),
            "stages_completed": sorted(done),
            "sc_obs": round(len(done) / spec["n"], 4),
            "records_seen": len(c_recs) + len(s_recs),
            "events": trace,
        })
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--attack", required=True, choices=sorted(ATTACKS))
    ap.add_argument("--port", type=int, default=None,
                    help="override the server port (default: the attack's)")
    ap.add_argument("--target", default=None, help="label for the result rows")
    ap.add_argument("--tool", default=None, help="label for the result rows")
    ap.add_argument("--json", default=None, help="write results here")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    results = analyse(a.pcap, a.attack, a.port, a.target, a.tool)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(results, fh, indent=2)
    if not a.quiet:
        if not results:
            print("no TCP session on that port in this capture")
        for r in results:
            print(f"{r['client']} -> {r['server']}  "
                  f"SC_obs = {r['completed_stages']}/{r['total_stages']} "
                  f"({r['sc_obs']:.0%})  stages={r['stages_completed']}")
            for e in r["events"]:
                print(f"    {e['stage']}. {e['name']}")
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
