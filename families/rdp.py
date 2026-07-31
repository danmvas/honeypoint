#!/usr/bin/env python3
"""
Família RDP-Recon — base compartilhada para drivers de honeypoint que
simulam CVEs cujo reconhecimento RDP começa com a mesma sequência:

  1. X.224 Connection Request
  2. Security Negotiation (declarada — sem NLA)
  3. MCS Connect Initial (GCC Conference Create Request)

Um driver desta família (ex: BlueKeep, MS12-020) herda de
`RDPFamilyDriver` e implementa apenas o ponto em que diverge de outras
CVEs da mesma família.

Diferença em relação à família SMB (families/smb.py): lá, a resolução
de variante acontece a partir de um único comando pós-Tree-Connect. Em
RDP, o sinal de divergência (ex: MS12-020 exige uma 2ª Attach User
Request e um Channel Join cross-user) só fica claro depois de uma
sequência curta de PDUs MCS — por isso `RDPConnectionHandler` mantém um
pequeno estado de sessão (IDs de usuário já alocados) durante a fase
pós-MCS-Connect, e só resolve a variante no primeiro Channel Join
Request, passando esse estado (`context`) para `matches_variant()` e
`handle_variant_stages()` em vez de só (command, parsed) como no SMB.

Este módulo é específico de RDP — por isso vive em families/, não em
framework/ (framework/README.md: o core nunca deve conter lógica de
protocolo) nem em drivers/ (não é uma CVE específica, é o tronco
compartilhado por várias).
"""

import logging
import os
import socket
import struct
from typing import Optional

from framework.base import DriverMetadata, StageDefinition
from framework.tracker import SCTracker
from framework import family

logger = logging.getLogger("honeypoint.rdp_family")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _sh = logging.StreamHandler()
    _sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(_sh)


# ============================================================
# RDP / X.224 / MCS PROTOCOL HELPERS (compartilhados por toda a família)
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


def identify_mcs_pdu(data: bytes) -> str:
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


def extract_channel_join_fields(data: bytes) -> tuple[int, int]:
    """Extrai (initiator_user_id, channel_id) de um Channel Join Request —
    ambos necessários para detectar um bind cross-user (sinal do MS12-020),
    além do canal em si (sinal do MS_T120 do BlueKeep)."""
    try:
        offset = 4
        if data[offset] == 0x02:
            offset += 3
        if offset + 5 <= len(data):
            initiator = struct.unpack(">H", data[offset+1:offset+3])[0]
            channel_id = struct.unpack(">H", data[offset+3:offset+5])[0]
            return initiator, channel_id
    except (IndexError, struct.error):
        pass
    return 0, 0


# ============================================================
# STAGES COMPARTILHADAS (1-3) — idênticas em toda a família RDP-Recon
# ============================================================

SHARED_RDP_STAGES = [
    StageDefinition(1, "X.224 Connection Request",
        "Scanner envia X.224 Connection Request com cookie", "RDP"),
    StageDefinition(2, "Security Negotiation",
        "Ausência de NLA confirma alvo vulnerável", "RDP"),
    StageDefinition(3, "MCS Connect Initial",
        "Scanner envia GCC Conference Create Request", "RDP"),
]


# ============================================================
# BASE DE FAMÍLIA E DISPATCH DINÂMICO
# (a orquestração genérica vem de framework.family; aqui só entra o
#  que é específico de RDP: qual ConnectionHandler instanciar)
# ============================================================

class _RDPPortListener(family.PortListener):
    """Listener RDP — só precisa dizer qual ConnectionHandler usar."""

    def _create_handler(self, sock: socket.socket, addr: tuple) -> "RDPConnectionHandler":
        return RDPConnectionHandler(self, sock, addr)


class RDPFamilyDriver(family.FamilyDriver):
    """Base para drivers que simulam CVEs de uma mesma família RDP.

    As stages 1-3 são tratadas uma única vez pelo listener compartilhado
    da porta; subclasses implementam apenas o ponto de divergência real
    da CVE simulada, que em RDP só fica claro no primeiro Channel Join
    Request (ver docstring do módulo).
    """

    _listener_cls = _RDPPortListener

    def matches_variant(self, event: str, context: dict) -> bool:
        """Decide, no primeiro Channel Join Request, se esta variante
        deve tratar o resto da conexão. `context` traz o estado
        acumulado da sessão (IDs de usuário já alocados, initiator e
        channel_id do Channel Join que disparou a resolução)."""
        raise NotImplementedError

    def handle_variant_stages(self, handler: "RDPConnectionHandler",
                               event: str, data: bytes, context: dict) -> Optional[bytes]:
        """Trata os eventos MCS a partir do ponto de divergência —
        aqui vive a lógica específica da CVE (stages 4+)."""
        raise NotImplementedError


class RDPConnectionHandler:
    """Gerencia uma conexão RDP individual, compartilhada por todas as
    variantes registradas na porta. Trata as stages 1-3 uma única vez e,
    no primeiro Channel Join Request, resolve dinamicamente qual
    variante (CVE) trata o resto da conexão."""

    def __init__(self, listener: _RDPPortListener, sock: socket.socket, addr: tuple):
        self.listener = listener
        self.sock = sock
        self.ip = addr[0]
        self.port = addr[1]
        self.user_id_counter = 1000
        self.attached_user_ids: list[int] = []
        self.channels_joined: list[int] = []
        self.tracker: Optional[SCTracker] = None
        self._pending_stages: list[tuple[int, str, dict]] = []
        self._resolved: Optional[RDPFamilyDriver] = None

    def handle(self) -> None:
        logger.info(f"🎯 Nova conexão RDP: {self.ip}:{self.port}")
        try:
            self.sock.settimeout(30)

            # ═══ B1: X.224 Connection Request ═══
            data = self._recv()
            if not data or len(data) < 11:
                return
            cr_info = parse_x224_cr(data)
            self._pending_stages.append((1, "X.224 Connection Request", cr_info))
            logger.info(f"🔍 [{self.ip}:{self.port}] X.224 CR: cookie={cr_info.get('cookie', 'none')}")
            self.sock.sendall(x224_cc(src_ref=cr_info.get("src_ref", 0)))

            # ═══ B2: Security Negotiation (sintética — sem troca de dados) ═══
            self._pending_stages.append((2, "Security Negotiation", {
                "selected_protocol": "PROTOCOL_RDP (0x00000000)",
                "nla_required": False,
            }))
            logger.info(f"🔓 [{self.ip}:{self.port}] Security: RDP nativo (sem NLA)")

            # ═══ B3: MCS Connect Initial ═══
            data = self._recv()
            if not data:
                return
            mcs_info = parse_mcs_connect_initial(data)
            self._pending_stages.append((3, "MCS Connect Initial", mcs_info))
            logger.info(f"🕵️ [{self.ip}:{self.port}] MCS: host='{mcs_info.get('client_hostname','')}'")
            self.sock.sendall(build_mcs_connect_response())

            # ═══ Domain / Attach User / Channel Join — dispatch dinâmico ═══
            max_pdus = 20
            for _ in range(max_pdus):
                data = self._recv()
                if not data:
                    break
                pdu_type = identify_mcs_pdu(data)

                if pdu_type == "erect_domain":
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Erect Domain Request")

                elif pdu_type == "attach_user":
                    self.user_id_counter += 1
                    new_id = self.user_id_counter
                    self.attached_user_ids.append(new_id)
                    logger.info(f"📡 [{self.ip}:{self.port}] MCS Attach User Request -> ID {new_id}")
                    self.sock.sendall(build_mcs_attach_confirm(new_id))

                elif pdu_type == "channel_join":
                    initiator, channel_id = extract_channel_join_fields(data)
                    self.channels_joined.append(channel_id)
                    context = {
                        "attached_user_ids": list(self.attached_user_ids),
                        "initiator": initiator,
                        "channel_id": channel_id,
                    }
                    if self._resolved is None:
                        self._resolved = self._resolve_variant("channel_join", context)
                        self.tracker = self._resolved._tracker
                        self.tracker.new_session(source_ip=self.ip)
                        for n, name, d in self._pending_stages:
                            self.tracker.complete_stage(n, name, source_ip=self.ip, data=d)
                        logger.info(f"➡️  [{self.ip}:{self.port}] Conexão resolvida para variante: "
                                    f"{self._resolved.get_metadata().name}")
                    response = self._resolved.handle_variant_stages(self, "channel_join", data, context)
                    if response:
                        self.sock.sendall(response)

                elif pdu_type == "send_data":
                    logger.info(f"📨 [{self.ip}:{self.port}] MCS Send Data ({len(data)} bytes)")
                    if self._resolved is not None:
                        response = self._resolved.handle_variant_stages(self, "send_data", data, {})
                        if response:
                            self.sock.sendall(response)
                    break

                else:
                    break

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
            self._finalize()
            logger.info(f"🔒 [{self.ip}:{self.port}] Encerrada")

    def _recv(self) -> Optional[bytes]:
        try:
            data = self.sock.recv(8192)
            return data if data else None
        except (socket.timeout, ConnectionResetError, OSError):
            return None

    def _resolve_variant(self, event: str, context: dict) -> RDPFamilyDriver:
        for variant in self.listener.variants:
            if not variant.is_default_variant() and variant.matches_variant(event, context):
                return variant
        return self.listener.effective_default_variant()

    def _finalize(self) -> None:
        if self._resolved is not None:
            tracker = self.tracker
        elif self._pending_stages:
            variant = self.listener.effective_default_variant()
            tracker = variant._tracker
            tracker.new_session(source_ip=self.ip)
            for n, name, d in self._pending_stages:
                tracker.complete_stage(n, name, source_ip=self.ip, data=d)
        else:
            return

        if tracker is not None and len(tracker._completed) > 0:
            tracker.finalize_session(deception_success=(tracker.get_sc() >= 0.8))
            tracker.print_status()
