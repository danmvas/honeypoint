#!/usr/bin/env python3
"""
BlueKeep Honeypoint — CVE-2019-0708 (RDP)
==========================================
Simula um servidor RDP vulnerável ao BlueKeep na porta 3389.
Emula as 5 etapas do protocolo RDP para maximizar Stage Coverage.

Etapas:
  B1: X.224 Connection Request  → Fingerprint cookie RDP
  B2: Security Negotiation      → Aceita RDP Security (sem NLA)
  B3: MCS Connect Initial       → Captura hostname, resolução, timezone
  B4: Channel Join               → Detecta bind MS_T120 em canal != 31
  B5: Exploit PDU               → Captura payload (Refresh Rect / RDPDR)

Uso em HOMELAB apenas — ferramenta de pesquisa acadêmica.
"""

import socket
import struct
import threading
import logging
import json
import datetime
import argparse
import os
import signal
import sys

from sc_tracker import SCTracker, print_comparison

# ============================================================
# LOGGING
# ============================================================
LOG_DIR = "./logs/bluekeep"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/bluekeep_honeypoint.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bluekeep_honeypoint")

json_logger = logging.getLogger("bluekeep_honeypoint.json")
jh = logging.FileHandler(f"{LOG_DIR}/bluekeep_events.jsonl")
jh.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(jh)
json_logger.setLevel(logging.INFO)


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
    """Empacota em TPKT: version(3) + reserved(0) + length(2 bytes BE)."""
    length = len(payload) + 4
    return struct.pack(">BBH", 3, 0, length) + payload


def x224_cc(src_ref: int = 0x0000, dst_ref: int = 0x1234) -> bytes:
    """
    X.224 Connection Confirm (CC) PDU.
    Sem RDP Negotiation Response = força RDP Security (não TLS/NLA).
    Isso simula um Windows vulnerável que não exige NLA.
    """
    # X.224 CC: length, CC type (0xD0), dst-ref, src-ref, class
    cc = struct.pack(">B", 11)                # Length indicator
    cc += struct.pack(">B", 0xD0)             # CC type
    cc += struct.pack(">H", dst_ref)          # Destination reference
    cc += struct.pack(">H", src_ref)          # Source reference
    cc += struct.pack(">B", 0x00)             # Class and options
    # RDP Negotiation Response - PROTOCOL_RDP (0x00000000) = no TLS, no NLA
    cc += struct.pack("<B", 0x02)             # Type: Neg RSP
    cc += struct.pack("<B", 0x00)             # Flags
    cc += struct.pack("<H", 0x0008)           # Length of neg
    cc += struct.pack("<I", 0x00000000)       # Selected protocol: PROTOCOL_RDP
    return tpkt_wrap(cc)


def x224_data_wrap(payload: bytes) -> bytes:
    """Empacota dados em X.224 Data TPDU + TPKT."""
    # X.224 DT (Data Transfer): length=2, DT type=0xF0, EOT=0x80
    dt = b'\x02\xf0\x80'
    return tpkt_wrap(dt + payload)


def ber_length_encode(tag: int, data: bytes, two_byte_tag: bool = False) -> bytes:
    """Codifica tag + length + data em BER."""
    if two_byte_tag:
        result = struct.pack(">H", tag)
    else:
        result = struct.pack(">B", tag)
    
    length = len(data)
    if length < 0x80:
        result += struct.pack(">B", length)
    elif length < 0x100:
        result += b'\x81' + struct.pack(">B", length)
    else:
        result += b'\x82' + struct.pack(">H", length)
    
    result += data
    return result


def build_mcs_connect_response() -> bytes:
    """
    MCS Connect Response com GCC Conference Create Response.
    Inclui SC_CORE + SC_NET + SC_SECURITY com certificado RSA proprietário.
    Header GCC segue formato exato do MS-RDPBCGR / Metasploit rex-rdp.
    """
    # ── Server Core Data (SC_CORE) ──
    sc_core = struct.pack("<H", 0x0C01)       # Header type
    sc_core += struct.pack("<H", 16)          # Length (inclui header)
    sc_core += struct.pack("<I", 0x00080004)  # Version: RDP 5.x/6.x/7.x/8.x
    sc_core += struct.pack("<I", 0x00000000)  # Client requested protocols
    sc_core += struct.pack("<I", 0x00000001)  # Early capability flags

    # ── Server Network Data (SC_NET) ──
    sc_net = struct.pack("<H", 0x0C03)        # Header type
    sc_net += struct.pack("<H", 12)           # Length
    sc_net += struct.pack("<H", 0x03EB)       # MCS channel ID (1003)
    sc_net += struct.pack("<H", 1)            # Channel count
    sc_net += struct.pack("<H", 0x03ED)       # Channel 1 ID
    sc_net += struct.pack("<H", 0)            # Padding

    # ── Server Security Data (SC_SECURITY) com RSA ──
    key_len = 64  # 512-bit RSA key
    modulus = bytes(range(1, key_len + 1))  # fake modulus

    # RSA Public Key Blob (MS-RDPBCGR 2.2.1.4.3.1.1.1)
    pubkey_blob = b'RSA1'
    pubkey_blob += struct.pack("<I", key_len)
    pubkey_blob += struct.pack("<I", key_len * 8)   # bitlen
    pubkey_blob += struct.pack("<I", key_len - 1)   # datalen
    pubkey_blob += struct.pack("<I", 0x10001)        # pubExp (65537)
    pubkey_blob += modulus

    sig_blob = bytes([0xAA] * key_len)
    sig_padding = b'\x00' * 8

    # Proprietary Certificate
    cert = struct.pack("<I", 0x00000001)     # dwVersion: CERT_CHAIN_VERSION_1
    cert += struct.pack("<I", 0x00000001)    # dwSigAlgId: SIGNATURE_ALG_RSA
    cert += struct.pack("<I", 0x00000001)    # dwKeyAlgId: KEY_EXCHANGE_ALG_RSA
    cert += struct.pack("<H", 0x0006)        # wPublicKeyBlobType: BB_RSA_KEY_BLOB
    cert += struct.pack("<H", len(pubkey_blob))
    cert += pubkey_blob
    cert += struct.pack("<H", 0x0008)        # wSignatureBlobType
    cert += struct.pack("<H", len(sig_blob) + len(sig_padding))
    cert += sig_blob + sig_padding

    server_random = os.urandom(32)

    sc_sec_body = struct.pack("<I", 0x00000001)  # Encryption method: 40-bit
    sc_sec_body += struct.pack("<I", 0x00000002) # Encryption level: CLIENT_COMPATIBLE
    sc_sec_body += struct.pack("<I", len(server_random))
    sc_sec_body += struct.pack("<I", len(cert))
    sc_sec_body += server_random + cert

    sc_sec = struct.pack("<H", 0x0C02)
    sc_sec += struct.pack("<H", len(sc_sec_body) + 4)
    sc_sec += sc_sec_body

    server_data = sc_core + sc_net + sc_sec

    # ── GCC Conference Create Response (T.124 PER) ──
    # Header fixo: ConnectGCCPDU + OID + nodeID + tag + result + userData key "McDn"
    # Extraído do Metasploit rex-rdp (formato exato que o scanner espera)
    gcc_header = (
        b'\x00\x05\x00\x14\x7c\x00\x01'   # ConnectData::conferenceCreateResponse + OID
        b'\x2a\x14\x76\x0a'                 # nodeID(PER) + tag
        b'\x01\x01\x00\x01\xc0\x00'         # result + userData set
        b'\x4d\x63\x44\x6e'                 # "McDn" H.221 key (Microsoft)
    )

    # PER length of server_data
    sd_len = len(server_data)
    if sd_len < 0x80:
        per_len = struct.pack(">B", sd_len)
    else:
        per_len = bytes([0x80 | ((sd_len >> 8) & 0x7F), sd_len & 0xFF])

    gcc_payload = gcc_header + per_len + server_data

    # ── MCS Connect-Response (BER) ──
    inner = b'\x0a\x01\x00'          # result: ENUMERATED 0 (success)
    inner += b'\x02\x01\x00'         # calledConnectId: INTEGER 0
    # domainParameters: SEQUENCE
    inner += b'\x30\x1a'
    inner += b'\x02\x01\x22'         # maxChannelIds: 34
    inner += b'\x02\x01\x03'         # maxUserIds: 3
    inner += b'\x02\x01\x00'         # maxTokenIds: 0
    inner += b'\x02\x01\x01'         # numPriorities: 1
    inner += b'\x02\x01\x00'         # minThroughput: 0
    inner += b'\x02\x01\x01'         # maxHeight: 1
    inner += b'\x02\x03\x00\xff\xff' # maxMCSPDUsize: 65535
    inner += b'\x02\x01\x02'         # protocolVersion: 2

    # userData: BER OCTET STRING
    ud_len = len(gcc_payload)
    if ud_len < 0x80:
        inner += b'\x04' + struct.pack(">B", ud_len)
    elif ud_len < 0x100:
        inner += b'\x04\x81' + struct.pack(">B", ud_len)
    else:
        inner += b'\x04\x82' + struct.pack(">H", ud_len)
    inner += gcc_payload

    # Connect-Response: tag 0x7F 0x66 + BER length
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
    """MCS Attach User Confirm."""
    # Tag: AttachUserConfirm (0x2E with result+initiator)
    payload = struct.pack(">B", 0x2e)
    payload += struct.pack(">B", 0x00)  # Result: successful
    payload += struct.pack(">H", user_id)
    return x224_data_wrap(payload)


def build_mcs_channel_join_confirm(user_id: int, channel_id: int) -> bytes:
    """MCS Channel Join Confirm."""
    payload = struct.pack(">B", 0x3e)
    payload += struct.pack(">B", 0x00)  # Result: successful
    payload += struct.pack(">H", user_id)
    payload += struct.pack(">H", channel_id)  # requested
    payload += struct.pack(">H", channel_id)  # channelId
    return x224_data_wrap(payload)


# ============================================================
# PARSER: X.224 Connection Request
# ============================================================

def parse_x224_cr(data: bytes) -> dict:
    """
    Parseia X.224 Connection Request para fingerprinting.
    Extrai: cookie RDP (contém hostname), requested protocols.
    """
    info = {}
    try:
        # TPKT: 4 bytes
        tpkt_len = struct.unpack(">H", data[2:4])[0]
        info["tpkt_length"] = tpkt_len

        # X.224 CR PDU
        x224_start = 4
        x224_len = data[x224_start]
        cr_type = data[x224_start + 1]
        info["x224_type"] = f"0x{cr_type:02x}"

        dst_ref = struct.unpack(">H", data[x224_start+2:x224_start+4])[0]
        src_ref = struct.unpack(">H", data[x224_start+4:x224_start+6])[0]
        info["dst_ref"] = dst_ref
        info["src_ref"] = src_ref

        # Cookie RDP (ex: "Cookie: mstshash=nmap\r\n")
        cookie_start = x224_start + 7
        remaining = data[cookie_start:]

        if remaining.startswith(b'Cookie:'):
            cr_end = remaining.find(b'\r\n')
            if cr_end > 0:
                cookie = remaining[:cr_end].decode('ascii', errors='replace')
                info["cookie"] = cookie
                # Extrair hostname do cookie
                if 'mstshash=' in cookie:
                    hostname = cookie.split('mstshash=')[1].strip()
                    info["rdp_client_name"] = hostname

                    # Fingerprint pela cookie
                    if hostname == "nmap":
                        info["tool_guess"] = "Nmap RDP scanner"
                    elif hostname.startswith("PC-") or hostname.startswith("WIN-"):
                        info["tool_guess"] = "Windows RDP Client"
                    elif hostname == "" or hostname == "hello":
                        info["tool_guess"] = "rdpscan / masscan"
                    else:
                        info["tool_guess"] = f"Unknown (hostname: {hostname})"

        # RDP Negotiation Request (se presente)
        # Buscar tipo 0x01 (Neg Request) no final
        neg_offset = x224_start + 1 + x224_len
        if neg_offset + 4 <= len(data):
            pass  # Some scanners don't include negotiation request
        else:
            # Check for negotiation data within the X.224 data
            for i in range(cookie_start, min(len(data) - 4, cookie_start + 200)):
                if data[i] == 0x01 and data[i+2:i+4] == b'\x08\x00':
                    neg_type = data[i]
                    neg_flags = data[i+1]
                    neg_len = struct.unpack("<H", data[i+2:i+4])[0]
                    req_protocols = struct.unpack("<I", data[i+4:i+8])[0]
                    info["neg_type"] = neg_type
                    info["requested_protocols"] = req_protocols
                    info["supports_tls"] = bool(req_protocols & 0x01)
                    info["supports_credssp"] = bool(req_protocols & 0x03)

                    if req_protocols == 0:
                        info["protocol_note"] = "RDP only - old client or scanner"
                    elif req_protocols & 0x03:
                        info["protocol_note"] = "Supports CredSSP/NLA"
                    break

    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)

    return info


def parse_mcs_connect_initial(data: bytes) -> dict:
    """
    Parseia MCS Connect Initial para extrair Client Core Data (GCC).
    Captura: hostname, resolução, teclado, timezone, build number.
    
    Estes dados vêm da máquina REAL do atacante — fingerprint riquíssimo.
    """
    info = {}
    try:
        # Procurar Client Core Data marker (0x01C0) dentro do pacote
        raw = data
        marker = struct.pack("<H", 0xC001)  # CS_CORE type
        pos = raw.find(marker)

        if pos < 0:
            info["parse_note"] = "CS_CORE not found in MCS Connect"
            return info

        cs = raw[pos:]
        header_type = struct.unpack("<H", cs[0:2])[0]
        header_len = struct.unpack("<H", cs[2:4])[0]
        info["cs_core_length"] = header_len

        if header_len < 132:
            info["parse_note"] = f"CS_CORE too short: {header_len}"
            return info

        # Version
        version = struct.unpack("<I", cs[4:8])[0]
        version_map = {
            0x00080001: "RDP 4.0", 0x00080004: "RDP 5.0/5.1/5.2/6.0/7.0/8.0",
            0x00080005: "RDP 8.1", 0x00080006: "RDP 8.1",
            0x0008000A: "RDP 10.0", 0x0008000B: "RDP 10.1",
            0x0008000C: "RDP 10.2", 0x0008000D: "RDP 10.3",
            0x0008000E: "RDP 10.4", 0x0008000F: "RDP 10.5",
            0x00080010: "RDP 10.6", 0x00080011: "RDP 10.7",
            0x00080012: "RDP 10.12",
        }
        info["rdp_version"] = version_map.get(version, f"Unknown(0x{version:08x})")

        # Desktop resolution
        desktop_w = struct.unpack("<H", cs[8:10])[0]
        desktop_h = struct.unpack("<H", cs[10:12])[0]
        info["desktop_width"] = desktop_w
        info["desktop_height"] = desktop_h
        info["resolution"] = f"{desktop_w}x{desktop_h}"

        # Color depth
        color_depth = struct.unpack("<H", cs[12:14])[0]
        depth_map = {0xCA00: "4 bpp", 0xCA01: "8 bpp",
                     0xCA02: "15 bpp", 0xCA03: "16 bpp", 0xCA04: "24 bpp"}
        info["color_depth"] = depth_map.get(color_depth, f"0x{color_depth:04x}")

        # SAS Sequence (always 0xAA03 for Ctrl+Alt+Del)
        sas = struct.unpack("<H", cs[14:16])[0]
        info["sas_sequence"] = f"0x{sas:04x}"

        # Keyboard layout
        kbd_layout = struct.unpack("<I", cs[16:20])[0]
        kbd_map = {
            0x00000409: "en-US", 0x00000809: "en-GB",
            0x00000416: "pt-BR", 0x00000816: "pt-PT",
            0x0000040C: "fr-FR", 0x00000407: "de-DE",
            0x00000419: "ru-RU", 0x00000411: "ja-JP",
            0x00000804: "zh-CN", 0x00000404: "zh-TW",
            0x0000040A: "es-ES",
        }
        info["keyboard_layout"] = kbd_map.get(kbd_layout, f"0x{kbd_layout:08x}")

        # Client build number
        build = struct.unpack("<I", cs[20:24])[0]
        info["client_build"] = build

        # Client name (Unicode, 32 bytes = 15 chars + null)
        client_name_raw = cs[24:56]
        client_name = client_name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
        info["client_hostname"] = client_name

        # Keyboard type
        kbd_type = struct.unpack("<I", cs[56:60])[0]
        kbd_types = {1: "IBM PC/XT (83-key)", 2: "Olivetti ICO (102-key)",
                     4: "IBM enhanced (101/102-key)", 7: "Japanese (106-key)"}
        info["keyboard_type"] = kbd_types.get(kbd_type, f"Type {kbd_type}")

        # Keyboard sub type and function keys
        info["keyboard_subtype"] = struct.unpack("<I", cs[60:64])[0]
        info["keyboard_function_keys"] = struct.unpack("<I", cs[64:68])[0]

        # Client product ID (offset 132 if length allows)
        if header_len >= 140:
            # Timezone info starts at offset 88 in CS_CORE
            try:
                tz_bias = struct.unpack("<i", cs[88:92])[0]
                info["timezone_bias_minutes"] = tz_bias

                tz_name_raw = cs[92:156]
                tz_name = tz_name_raw.decode('utf-16-le', errors='replace').rstrip('\x00')
                if tz_name:
                    info["timezone_name"] = tz_name
            except (IndexError, struct.error):
                pass

        # Fingerprint tool
        if client_name.lower() in ("", "PC"):
            info["tool_guess"] = "Scanner genérico / script"
        elif "nmap" in client_name.lower():
            info["tool_guess"] = "Nmap"
        elif "PC-" in client_name or "WIN-" in client_name or "DESKTOP-" in client_name:
            info["tool_guess"] = "Windows RDP Client real"

    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)

    return info


# ============================================================
# CONNECTION HANDLER
# ============================================================

class BlueKeepHandler:
    """Gerencia uma conexão RDP individual com tracking SC."""

    def __init__(self, sock: socket.socket, addr: tuple):
        self.sock = sock
        self.ip = addr[0]
        self.port = addr[1]
        self.sc = SCTracker.bluekeep(self.ip, self.port)
        self.user_id = 1001
        self.channels_joined = []

    def handle(self):
        logger.info(f"🎯 Nova conexão RDP: {self.ip}:{self.port}")
        log_ev("rdp_connection_open", self.ip, self.port, {})

        try:
            self.sock.settimeout(30)

            # ═══ B1: X.224 Connection Request ═══
            self.sc.start_stage("B1")
            data = self._recv()
            if not data or len(data) < 11:
                self.sc.fail_stage("B1", "No CR PDU received")
                return

            cr_info = parse_x224_cr(data)
            tool = cr_info.get("tool_guess", "")
            if tool:
                self.sc.tool_detected = tool

            logger.info(
                f"🔍 [{self.ip}:{self.port}] X.224 CR: "
                f"cookie={cr_info.get('cookie', 'none')} "
                f"client={cr_info.get('rdp_client_name', '?')}"
            )
            self.sc.complete_stage("B1", cr_info)
            log_ev("rdp_x224_cr", self.ip, self.port, cr_info)

            # Enviar X.224 CC (sem NLA = parece vulnerável)
            cc = x224_cc(src_ref=cr_info.get("src_ref", 0))
            self.sock.sendall(cc)

            # ═══ B2: Security Negotiation (implícita no CC) ═══
            self.sc.start_stage("B2")
            # O CC já foi enviado sem NLA — isso completa a negociação
            self.sc.complete_stage("B2", {
                "selected_protocol": "PROTOCOL_RDP (0x00000000)",
                "nla_required": False,
                "note": "Sem NLA = simula Windows vulnerável ao BlueKeep"
            })
            logger.info(f"🔓 [{self.ip}:{self.port}] Security: RDP nativo (sem NLA)")

            # ═══ B3: MCS Connect Initial ═══
            self.sc.start_stage("B3")
            data = self._recv()
            if not data:
                self.sc.fail_stage("B3", "No MCS Connect Initial")
                return

            mcs_info = parse_mcs_connect_initial(data)

            hostname = mcs_info.get("client_hostname", "")
            resolution = mcs_info.get("resolution", "")
            keyboard = mcs_info.get("keyboard_layout", "")
            timezone = mcs_info.get("timezone_name", "")

            logger.info(
                f"🕵️ [{self.ip}:{self.port}] MCS FINGERPRINT: "
                f"host='{hostname}' res={resolution} "
                f"kbd={keyboard} tz={timezone}"
            )

            if mcs_info.get("tool_guess"):
                self.sc.tool_detected = mcs_info["tool_guess"]

            self.sc.complete_stage("B3", mcs_info)
            log_ev("rdp_mcs_connect", self.ip, self.port, mcs_info)

            # Enviar MCS Connect Response
            mcs_resp = build_mcs_connect_response()
            self.sock.sendall(mcs_resp)

            # ═══ B4: MCS Domain / Attach / Channel Join ═══
            self.sc.start_stage("B4")

            # Loop para processar MCS Erect Domain, Attach User, Channel Joins
            b4_completed = False
            ms_t120_attempted = False
            max_pdus = 20  # Limite de PDUs para evitar loop infinito

            for _ in range(max_pdus):
                data = self._recv()
                if not data:
                    break

                # Parsear tipo do MCS PDU
                pdu_type = self._identify_mcs_pdu(data)

                if pdu_type == "erect_domain":
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Erect Domain Request")
                    # Não requer resposta

                elif pdu_type == "attach_user":
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Attach User Request")
                    confirm = build_mcs_attach_confirm(self.user_id)
                    self.sock.sendall(confirm)

                elif pdu_type == "channel_join":
                    channel_id = self._extract_channel_id(data)
                    self.channels_joined.append(channel_id)
                    logger.info(
                        f"📡 [{self.ip}:{self.port}] "
                        f"MCS Channel Join: {channel_id}"
                    )

                    # MS_T120 check — canal 31 é o padrão seguro
                    if channel_id == 31 or channel_id == 0:
                        ms_t120_attempted = True
                        logger.warning(
                            f"🚨 [{self.ip}:{self.port}] "
                            f"MS_T120 channel bind detectado! (canal {channel_id})"
                        )

                    confirm = build_mcs_channel_join_confirm(self.user_id, channel_id)
                    self.sock.sendall(confirm)
                    b4_completed = True

                elif pdu_type == "send_data":
                    # Pode ser Client Security Exchange, Client Info, ou exploit
                    logger.info(
                        f"📨 [{self.ip}:{self.port}] "
                        f"MCS Send Data ({len(data)} bytes)"
                    )

                    if b4_completed:
                        # Avançar para B5
                        self.sc.complete_stage("B4", {
                            "channels_joined": self.channels_joined,
                            "ms_t120_attempted": ms_t120_attempted,
                            "total_channels": len(self.channels_joined)
                        })

                        # ═══ B5: Exploit PDU ═══
                        self.sc.start_stage("B5")
                        log_ev("rdp_possible_exploit", self.ip, self.port, {
                            "alert": "🚨 POSSÍVEL EXPLOIT BLUEKEEP!",
                            "raw_hex": data.hex(),
                            "pdu_size": len(data),
                            "channels": self.channels_joined,
                            "severity": "HIGH"
                        })
                        logger.warning(
                            f"🚨🚨🚨 [{self.ip}:{self.port}] "
                            f"POSSÍVEL EXPLOIT BLUEKEEP! "
                            f"PDU de {len(data)} bytes após channel join"
                        )
                        self.sc.complete_stage("B5", {
                            "payload_size": len(data),
                            "payload_hex_preview": data[:128].hex()
                        })
                        break

                    # Responder com OK genérico para manter conexão
                    break

                else:
                    logger.info(
                        f"❓ [{self.ip}:{self.port}] "
                        f"PDU desconhecido: {data[:8].hex()}"
                    )
                    break

            if b4_completed and not self.sc.stages[3].status.value == "completed":
                self.sc.complete_stage("B4", {
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

            # Relatório SC
            self.sc.print_summary()
            report_path = self.sc.save_report()

            log_ev("rdp_connection_close", self.ip, self.port,
                   self.sc.report())

            # Comparar com literatura
            print_comparison("BlueKeep", self.sc.sc_score)

    def _recv(self) -> bytes | None:
        """Recebe dados do socket."""
        try:
            data = self.sock.recv(8192)
            return data if data else None
        except (socket.timeout, ConnectionResetError, OSError):
            return None

    def _identify_mcs_pdu(self, data: bytes) -> str:
        """Identifica o tipo de PDU MCS a partir dos bytes."""
        # Pular TPKT (4 bytes) + X.224 DT (3 bytes)
        if len(data) < 8:
            return "unknown"

        # TPKT check
        if data[0] != 3:
            return "unknown"

        offset = 4  # após TPKT

        # X.224 Data TPDU
        if data[offset] == 0x02 and data[offset+1] == 0xf0:
            offset += 3  # pular X.224 DT header

        if offset >= len(data):
            return "unknown"

        mcs_type = data[offset]

        # MCS PDU types (application tags)
        if mcs_type == 0x04:
            return "erect_domain"
        elif mcs_type == 0x28 or mcs_type == 0x2a:
            return "attach_user"
        elif mcs_type == 0x38 or mcs_type == 0x3a:
            return "channel_join"
        elif mcs_type == 0x64 or mcs_type == 0x68:
            return "send_data"
        else:
            # BER encoded - check for specific patterns
            if data[offset:offset+2] == b'\x04\x01':
                return "erect_domain"
            return "unknown"

    def _extract_channel_id(self, data: bytes) -> int:
        """Extrai channel ID de um Channel Join Request."""
        try:
            # Find MCS Channel Join Request after TPKT + X.224
            offset = 4  # TPKT
            if data[offset] == 0x02:
                offset += 3  # X.224 DT

            # Channel Join: type(1) + userId(2) + channelId(2)
            if offset + 5 <= len(data):
                channel_id = struct.unpack(">H", data[offset+3:offset+5])[0]
                return channel_id
        except (IndexError, struct.error):
            pass
        return 0


# ============================================================
# MAIN SERVER
# ============================================================

class BlueKeepHoneypoint:
    def __init__(self, host="0.0.0.0", port=3389):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
        except PermissionError:
            logger.error(f"❌ Sem permissão na porta {self.port}. Use sudo.")
            sys.exit(1)
        except OSError as e:
            logger.error(f"❌ Bind error: {e}")
            sys.exit(1)

        self.server_socket.listen(10)
        self.running = True

        logger.info("=" * 60)
        logger.info("🍯 BLUEKEEP HONEYPOINT ATIVO")
        logger.info(f"🌐 Escutando em {self.host}:{self.port}")
        logger.info(f"📁 Logs: {LOG_DIR}/")
        logger.info(f"📋 SC Reports: {LOG_DIR}/sc_BlueKeep_*.json")
        logger.info("=" * 60)

        try:
            signal.signal(signal.SIGINT, self._shutdown)
            signal.signal(signal.SIGTERM, self._shutdown)
        except ValueError:
            pass  # Rodando em thread — launcher gerencia signals

        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_sock, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue

                handler = BlueKeepHandler(client_sock, client_addr)
                thread = threading.Thread(
                    target=handler.handle, daemon=True,
                    name=f"rdp-{client_addr[0]}:{client_addr[1]}"
                )
                thread.start()

            except Exception as e:
                if self.running:
                    logger.error(f"❌ Accept error: {e}")

    def _shutdown(self, signum, frame):
        logger.info("\n🛑 Encerrando BlueKeep honeypoint...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BlueKeep Honeypoint — CVE-2019-0708 RDP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 honeypoint_bluekeep.py                    # porta 3389
  sudo python3 honeypoint_bluekeep.py -p 3390            # porta alternativa

Testar:
  nmap --script rdp-vuln-ms12-020 -p 3389 <IP>
  msfconsole: use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
  rdpscan <IP>

Stage Coverage:
  Relatório JSON salvo em /var/log/honeypoint/sc_BlueKeep_*.json
        """
    )
    parser.add_argument("-p", "--port", type=int, default=3389)
    parser.add_argument("-b", "--bind", type=str, default="0.0.0.0")

    args = parser.parse_args()
    honeypoint = BlueKeepHoneypoint(host=args.bind, port=args.port)
    honeypoint.start()
