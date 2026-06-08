#!/usr/bin/env python3
"""
Driver: BlueKeep (CVE-2019-0708)
=================================
Honeypoint que simula um servidor RDP vulnerável ao BlueKeep,
enganando o scanner Metasploit auxiliary/scanner/rdp/cve_2019_0708_bluekeep.

Stages do reconhecimento:
  B1: X.224 Connection Request    — Scanner inicia conexão RDP
  B2: Security Negotiation        — Ausência de NLA confirma alvo vulnerável
  B3: MCS Connect Initial         — Scanner envia GCC Conference Create Request
  B4: Channel Join                — Scanner solicita canais virtuais
  B5: Exploit PDU                 — Scanner envia payload de exploit
"""

import socket
import struct
import threading
import logging
import json
import datetime
import os
import signal
import sys
from typing import Optional

from framework.base import HoneyPointDriver, DriverMetadata, StageDefinition
from framework.tracker import SCTracker

# ============================================================
# LOGGING SETUP
# ============================================================
LOG_DIR = "./logs/bluekeep"
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("honeypoint.bluekeep")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(f"{LOG_DIR}/bluekeep_honeypoint.log")
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(sh)

json_logger = logging.getLogger("honeypoint.bluekeep.json")
if not json_logger.handlers:
    json_logger.setLevel(logging.INFO)
    jh = logging.FileHandler(f"{LOG_DIR}/bluekeep_events.jsonl")
    jh.setFormatter(logging.Formatter('%(message)s'))
    json_logger.addHandler(jh)


def log_ev(event_type, ip, port, details):
    ev = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type, "src_ip": ip, "src_port": port,
        "details": details
    }
    json_logger.info(json.dumps(ev, ensure_ascii=False))


# ============================================================
# RDP / X.224 / MCS PROTOCOL HELPERS
# ============================================================

def tpkt_wrap(payload: bytes) -> bytes:
    length = len(payload) + 4
    return struct.pack(">BBH", 3, 0, length) + payload


def x224_cc(src_ref: int = 0x0000, dst_ref: int = 0x1234) -> bytes:
    cc = struct.pack(">B", 11)
    cc += struct.pack(">B", 0xD0)
    cc += struct.pack(">H", dst_ref)
    cc += struct.pack(">H", src_ref)
    cc += struct.pack(">B", 0x00)
    cc += struct.pack("<B", 0x02)
    cc += struct.pack("<B", 0x00)
    cc += struct.pack("<H", 0x0008)
    cc += struct.pack("<I", 0x00000000)
    return tpkt_wrap(cc)


def x224_data_wrap(payload: bytes) -> bytes:
    dt = b'\x02\xf0\x80'
    return tpkt_wrap(dt + payload)


def build_mcs_connect_response() -> bytes:
    # SC_CORE
    sc_core = struct.pack("<H", 0x0C01)
    sc_core += struct.pack("<H", 16)
    sc_core += struct.pack("<I", 0x00080004)
    sc_core += struct.pack("<I", 0x00000000)
    sc_core += struct.pack("<I", 0x00000001)

    # SC_NET
    sc_net = struct.pack("<H", 0x0C03)
    sc_net += struct.pack("<H", 12)
    sc_net += struct.pack("<H", 0x03EB)
    sc_net += struct.pack("<H", 1)
    sc_net += struct.pack("<H", 0x03ED)
    sc_net += struct.pack("<H", 0)

    # SC_SECURITY with RSA cert
    key_len = 64
    modulus = bytes(range(1, key_len + 1))
    pubkey_blob = b'RSA1'
    pubkey_blob += struct.pack("<I", key_len)
    pubkey_blob += struct.pack("<I", key_len * 8)
    pubkey_blob += struct.pack("<I", key_len - 1)
    pubkey_blob += struct.pack("<I", 0x10001)
    pubkey_blob += modulus
    sig_blob = bytes([0xAA] * key_len)
    sig_padding = b'\x00' * 8
    cert = struct.pack("<I", 0x00000001)
    cert += struct.pack("<I", 0x00000001)
    cert += struct.pack("<I", 0x00000001)
    cert += struct.pack("<H", 0x0006)
    cert += struct.pack("<H", len(pubkey_blob))
    cert += pubkey_blob
    cert += struct.pack("<H", 0x0008)
    cert += struct.pack("<H", len(sig_blob) + len(sig_padding))
    cert += sig_blob + sig_padding
    server_random = os.urandom(32)
    sc_sec_body = struct.pack("<I", 0x00000001)
    sc_sec_body += struct.pack("<I", 0x00000002)
    sc_sec_body += struct.pack("<I", len(server_random))
    sc_sec_body += struct.pack("<I", len(cert))
    sc_sec_body += server_random + cert
    sc_sec = struct.pack("<H", 0x0C02)
    sc_sec += struct.pack("<H", len(sc_sec_body) + 4)
    sc_sec += sc_sec_body

    server_data = sc_core + sc_net + sc_sec

    # GCC Conference Create Response
    gcc_header = (
        b'\x00\x05\x00\x14\x7c\x00\x01'
        b'\x2a\x14\x76\x0a'
        b'\x01\x01\x00\x01\xc0\x00'
        b'\x4d\x63\x44\x6e'
    )
    sd_len = len(server_data)
    if sd_len < 0x80:
        per_len = struct.pack(">B", sd_len)
    else:
        per_len = bytes([0x80 | ((sd_len >> 8) & 0x7F), sd_len & 0xFF])
    gcc_payload = gcc_header + per_len + server_data

    # MCS Connect-Response (BER)
    inner = b'\x0a\x01\x00'
    inner += b'\x02\x01\x00'
    inner += b'\x30\x1a'
    inner += b'\x02\x01\x22'
    inner += b'\x02\x01\x03'
    inner += b'\x02\x01\x00'
    inner += b'\x02\x01\x01'
    inner += b'\x02\x01\x00'
    inner += b'\x02\x01\x01'
    inner += b'\x02\x03\x00\xff\xff'
    inner += b'\x02\x01\x02'
    ud_len = len(gcc_payload)
    if ud_len < 0x80:
        inner += b'\x04' + struct.pack(">B", ud_len)
    elif ud_len < 0x100:
        inner += b'\x04\x81' + struct.pack(">B", ud_len)
    else:
        inner += b'\x04\x82' + struct.pack(">H", ud_len)
    inner += gcc_payload

    resp_len = len(inner)
    if resp_len < 0x80:
        mcs = b'\x7f\x66' + struct.pack(">B", resp_len)
    elif resp_len < 0x100:
        mcs = b'\x7f\x66\x81' + struct.pack(">B", resp_len)
    else:
        mcs = b'\x7f\x66\x82' + struct.pack(">H", resp_len)
    mcs += inner
    return x224_data_wrap(mcs)


def build_mcs_attach_confirm(user_id: int = 1001) -> bytes:
    payload = struct.pack(">B", 0x2e)
    payload += struct.pack(">B", 0x00)
    payload += struct.pack(">H", user_id)
    return x224_data_wrap(payload)


def build_mcs_channel_join_confirm(user_id: int, channel_id: int) -> bytes:
    payload = struct.pack(">B", 0x3e)
    payload += struct.pack(">B", 0x00)
    payload += struct.pack(">H", user_id)
    payload += struct.pack(">H", channel_id)
    payload += struct.pack(">H", channel_id)
    return x224_data_wrap(payload)


# ============================================================
# PARSERS
# ============================================================

def parse_x224_cr(data: bytes) -> dict:
    info = {}
    try:
        tpkt_len = struct.unpack(">H", data[2:4])[0]
        info["tpkt_length"] = tpkt_len
        x224_start = 4
        x224_len = data[x224_start]
        cr_type = data[x224_start + 1]
        info["x224_type"] = f"0x{cr_type:02x}"
        dst_ref = struct.unpack(">H", data[x224_start+2:x224_start+4])[0]
        src_ref = struct.unpack(">H", data[x224_start+4:x224_start+6])[0]
        info["dst_ref"] = dst_ref
        info["src_ref"] = src_ref
        cookie_start = x224_start + 7
        remaining = data[cookie_start:]
        if remaining.startswith(b'Cookie:'):
            cr_end = remaining.find(b'\r\n')
            if cr_end > 0:
                cookie = remaining[:cr_end].decode('ascii', errors='replace')
                info["cookie"] = cookie
                if 'mstshash=' in cookie:
                    hostname = cookie.split('mstshash=')[1].strip()
                    info["rdp_client_name"] = hostname
                    if hostname == "nmap":
                        info["tool_guess"] = "Nmap RDP scanner"
                    elif hostname.startswith("PC-") or hostname.startswith("WIN-"):
                        info["tool_guess"] = "Windows RDP Client"
                    elif hostname in ("", "hello"):
                        info["tool_guess"] = "rdpscan / masscan"
                    else:
                        info["tool_guess"] = f"Unknown ({hostname})"
        for i in range(cookie_start, min(len(data) - 4, cookie_start + 200)):
            if data[i] == 0x01 and data[i+2:i+4] == b'\x08\x00':
                req_protocols = struct.unpack("<I", data[i+4:i+8])[0]
                info["requested_protocols"] = req_protocols
                info["supports_tls"] = bool(req_protocols & 0x01)
                info["supports_credssp"] = bool(req_protocols & 0x03)
                break
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


def parse_mcs_connect_initial(data: bytes) -> dict:
    info = {}
    try:
        raw = data
        marker = struct.pack("<H", 0xC001)
        pos = raw.find(marker)
        if pos < 0:
            info["parse_note"] = "CS_CORE not found"
            return info
        cs = raw[pos:]
        header_len = struct.unpack("<H", cs[2:4])[0]
        info["cs_core_length"] = header_len
        if header_len < 132:
            return info
        version = struct.unpack("<I", cs[4:8])[0]
        version_map = {
            0x00080001: "RDP 4.0", 0x00080004: "RDP 5.x-8.0",
            0x00080005: "RDP 8.1", 0x0008000A: "RDP 10.0",
        }
        info["rdp_version"] = version_map.get(version, f"0x{version:08x}")
        desktop_w = struct.unpack("<H", cs[8:10])[0]
        desktop_h = struct.unpack("<H", cs[10:12])[0]
        info["resolution"] = f"{desktop_w}x{desktop_h}"
        kbd_layout = struct.unpack("<I", cs[16:20])[0]
        kbd_map = {
            0x00000409: "en-US", 0x00000809: "en-GB",
            0x00000416: "pt-BR", 0x0000040C: "fr-FR",
            0x00000407: "de-DE", 0x00000419: "ru-RU",
        }
        info["keyboard_layout"] = kbd_map.get(kbd_layout, f"0x{kbd_layout:08x}")
        info["client_build"] = struct.unpack("<I", cs[20:24])[0]
        client_name_raw = cs[24:56]
        client_name = client_name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
        info["client_hostname"] = client_name
        if header_len >= 140:
            try:
                tz_bias = struct.unpack("<i", cs[88:92])[0]
                info["timezone_bias_minutes"] = tz_bias
                tz_name = cs[92:156].decode('utf-16-le', errors='replace').rstrip('\x00')
                if tz_name:
                    info["timezone_name"] = tz_name
            except (IndexError, struct.error):
                pass
        if client_name.lower() in ("", "pc"):
            info["tool_guess"] = "Scanner genérico"
        elif "nmap" in client_name.lower():
            info["tool_guess"] = "Nmap"
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


# ============================================================
# DRIVER CLASS
# ============================================================

class BlueKeepDriver(HoneyPointDriver):
    """Driver para simulação de BlueKeep/CVE-2019-0708."""

    def __init__(self):
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._tracker: Optional[SCTracker] = None

    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            name="BlueKeep",
            cve="CVE-2019-0708",
            cve_alias="BlueKeep",
            protocol="RDP",
            default_port=3389,
            scanner_module="auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
            scanner_tool="Metasploit Framework",
            description="Simula servidor RDP vulnerável ao BlueKeep",
            stages=[
                StageDefinition(1, "X.224 Connection Request",
                    "Scanner envia X.224 Connection Request com cookie", "RDP"),
                StageDefinition(2, "Security Negotiation",
                    "Ausência de NLA confirma alvo vulnerável", "RDP"),
                StageDefinition(3, "MCS Connect Initial",
                    "Scanner envia GCC Conference Create Request", "RDP"),
                StageDefinition(4, "Channel Join",
                    "Scanner solicita join nos canais virtuais", "RDP"),
                StageDefinition(5, "Exploit PDU",
                    "Scanner envia payload de exploit", "RDP"),
            ]
        )

    def start(self, port: int, tracker: SCTracker) -> None:
        self._tracker = tracker
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("0.0.0.0", port))
        self._server_socket.listen(10)
        logger.info(f"🍯 BlueKeep Honeypoint escutando na porta {port}")
        log_ev("server_start", "0.0.0.0", port, {"bind_port": port})

        while self._running:
            try:
                self._server_socket.settimeout(1.0)
                try:
                    client_sock, addr = self._server_socket.accept()
                except socket.timeout:
                    continue
                handler = _BKHandler(client_sock, addr, self._tracker)
                t = threading.Thread(target=handler.handle, daemon=True,
                                     name=f"rdp-{addr[0]}:{addr[1]}")
                t.start()
            except OSError:
                break

    def stop(self) -> None:
        self._running = False
        if self._server_socket:
            self._server_socket.close()


# ============================================================
# CONNECTION HANDLER (internal)
# ============================================================

class _BKHandler:
    """Gerencia uma conexão RDP individual."""

    def __init__(self, sock: socket.socket, addr: tuple, tracker: SCTracker):
        self.sock = sock
        self.ip = addr[0]
        self.port = addr[1]
        self.tracker = tracker
        self.user_id = 1001
        self.channels_joined = []

    def handle(self):
        logger.info(f"🎯 Nova conexão RDP: {self.ip}:{self.port}")
        log_ev("rdp_connection_open", self.ip, self.port, {})
        self.tracker.new_session(source_ip=self.ip)

        try:
            self.sock.settimeout(30)

            # ═══ B1: X.224 Connection Request ═══
            data = self._recv()
            if not data or len(data) < 11:
                return
            cr_info = parse_x224_cr(data)
            self.tracker.complete_stage(1, "X.224 Connection Request",
                source_ip=self.ip, data=cr_info)
            logger.info(f"🔍 [{self.ip}:{self.port}] X.224 CR: cookie={cr_info.get('cookie', 'none')}")
            log_ev("rdp_x224_cr", self.ip, self.port, cr_info)
            cc = x224_cc(src_ref=cr_info.get("src_ref", 0))
            self.sock.sendall(cc)

            # ═══ B2: Security Negotiation ═══
            self.tracker.complete_stage(2, "Security Negotiation",
                source_ip=self.ip, data={
                    "selected_protocol": "PROTOCOL_RDP (0x00000000)",
                    "nla_required": False,
                })
            logger.info(f"🔓 [{self.ip}:{self.port}] Security: RDP nativo (sem NLA)")

            # ═══ B3: MCS Connect Initial ═══
            data = self._recv()
            if not data:
                return
            mcs_info = parse_mcs_connect_initial(data)
            hostname = mcs_info.get("client_hostname", "")
            resolution = mcs_info.get("resolution", "")
            keyboard = mcs_info.get("keyboard_layout", "")
            timezone = mcs_info.get("timezone_name", "")
            logger.info(f"🕵️ [{self.ip}:{self.port}] MCS: host='{hostname}' res={resolution} kbd={keyboard} tz={timezone}")
            self.tracker.complete_stage(3, "MCS Connect Initial",
                source_ip=self.ip, data=mcs_info)
            log_ev("rdp_mcs_connect", self.ip, self.port, mcs_info)
            mcs_resp = build_mcs_connect_response()
            self.sock.sendall(mcs_resp)

            # ═══ B4: MCS Domain / Attach / Channel Join ═══
            b4_completed = False
            ms_t120_attempted = False
            max_pdus = 20

            for _ in range(max_pdus):
                data = self._recv()
                if not data:
                    break
                pdu_type = self._identify_mcs_pdu(data)

                if pdu_type == "erect_domain":
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Erect Domain Request")

                elif pdu_type == "attach_user":
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Attach User Request")
                    self.sock.sendall(build_mcs_attach_confirm(self.user_id))

                elif pdu_type == "channel_join":
                    channel_id = self._extract_channel_id(data)
                    self.channels_joined.append(channel_id)
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Channel Join: {channel_id}")
                    if channel_id == 31 or channel_id == 0:
                        ms_t120_attempted = True
                        logger.warning(f"🚨 [{self.ip}:{self.port}] MS_T120 channel bind! (canal {channel_id})")
                    self.sock.sendall(build_mcs_channel_join_confirm(self.user_id, channel_id))
                    b4_completed = True

                elif pdu_type == "send_data":
                    logger.info(f"📨 [{self.ip}:{self.port}] MCS Send Data ({len(data)} bytes)")
                    if b4_completed:
                        self.tracker.complete_stage(4, "Channel Join",
                            source_ip=self.ip, data={
                                "channels_joined": self.channels_joined,
                                "ms_t120_attempted": ms_t120_attempted,
                            })

                        # ═══ B5: Exploit PDU ═══
                        log_ev("rdp_possible_exploit", self.ip, self.port, {
                            "alert": "POSSÍVEL EXPLOIT BLUEKEEP",
                            "pdu_size": len(data), "channels": self.channels_joined,
                        })
                        logger.warning(f"🚨 [{self.ip}:{self.port}] POSSÍVEL EXPLOIT! {len(data)} bytes")
                        self.tracker.complete_stage(5, "Exploit PDU",
                            source_ip=self.ip, data={
                                "payload_size": len(data),
                                "payload_hex_preview": data[:128].hex()
                            })
                        break
                    break
                else:
                    break

            if b4_completed and 4 not in self.tracker._completed:
                self.tracker.complete_stage(4, "Channel Join",
                    source_ip=self.ip, data={
                        "channels_joined": self.channels_joined,
                        "ms_t120_attempted": ms_t120_attempted,
                    })

        except socket.timeout:
            logger.info(f"⏰ [{self.ip}:{self.port}] Timeout")
        except ConnectionResetError:
            logger.info(f"🔌 [{self.ip}:{self.port}] Conexão resetada")
        except BrokenPipeError:
            logger.info(f"🔌 [{self.ip}:{self.port}] Broken pipe")
        except Exception as e:
            logger.error(f"❌ [{self.ip}:{self.port}] Erro: {e}")
        finally:
            self.sock.close()
            self.tracker.finalize_session(
                deception_success=(self.tracker.get_sc() >= 0.8)
            )
            self.tracker.print_status()
            log_ev("rdp_connection_close", self.ip, self.port, {
                "sc": self.tracker.get_sc_display(),
                "channels": self.channels_joined
            })

    def _recv(self) -> bytes | None:
        try:
            data = self.sock.recv(8192)
            return data if data else None
        except (socket.timeout, ConnectionResetError, OSError):
            return None

    def _identify_mcs_pdu(self, data: bytes) -> str:
        if len(data) < 8:
            return "unknown"
        if data[0] != 3:
            return "unknown"
        offset = 4
        if data[offset] == 0x02 and data[offset+1] == 0xf0:
            offset += 3
        if offset >= len(data):
            return "unknown"
        mcs_type = data[offset]
        if mcs_type == 0x04:
            return "erect_domain"
        elif mcs_type in (0x28, 0x2a):
            return "attach_user"
        elif mcs_type in (0x38, 0x3a):
            return "channel_join"
        elif mcs_type in (0x64, 0x68):
            return "send_data"
        elif data[offset:offset+2] == b'\x04\x01':
            return "erect_domain"
        return "unknown"

    def _extract_channel_id(self, data: bytes) -> int:
        try:
            offset = 4
            if data[offset] == 0x02:
                offset += 3
            if offset + 5 <= len(data):
                return struct.unpack(">H", data[offset+3:offset+5])[0]
        except (IndexError, struct.error):
            pass
        return 0