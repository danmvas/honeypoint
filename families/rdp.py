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
RDP, o sinal de divergência só fica claro depois de uma sequência curta
de PDUs MCS — por isso `RDPConnectionHandler` mantém um pequeno estado de
sessão (IDs de usuário já alocados, canais estáticos pedidos no CS_NET) e
consulta as variantes a cada Attach User Request (o MS12-020 se revela no
2º) e no primeiro Channel Join Request (onde a variante default assume se
nenhuma outra reconhecer), passando esse estado (`context`) para
`matches_variant()` e `handle_variant_stages()`. Conexões que terminam
antes disso são registradas sob a família (tronco), não sob uma variante.

Depois dos Channel Joins, o handler conduz a sequência de conexão RDP —
Security Exchange, licença (valid client), Demand Active, finalização e a
primeira atualização de tela — e entrega às variantes os dados que
chegam nos canais virtuais estáticos (evento "channel_data"). É ali que
os scanners de BlueKeep enviam a sonda MS_T120.

Este módulo é específico de RDP — por isso vive em families/, não em
framework/ (framework/README.md: o core nunca deve conter lógica de
protocolo) nem em drivers/ (não é uma CVE específica, é o tronco
compartilhado por várias).
"""

import logging
import os
import select
import socket
import struct
import time
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
# CONSTANTES MCS / RDP SECURITY (MS-RDPBCGR)
# ============================================================

MCS_SERVER_CHANNEL = 0x03EA         # 1002: usuário MCS do servidor (initiator)
MCS_IO_CHANNEL = 0x03EB             # 1003: canal de I/O (global)
MCS_FIRST_STATIC_CHANNEL = 0x03EC   # 1004: canais virtuais estáticos, na ordem do CS_NET
SEC_EXCHANGE_PKT = 0x0001
SEC_ENCRYPT = 0x0008
SEC_INFO_PKT = 0x0040
SEC_LICENSE_PKT = 0x0080
SHARE_ID = 0x000103EA


# ============================================================
# RDP / X.224 / MCS PROTOCOL HELPERS (compartilhados por toda a família)
# ============================================================

def tpkt_wrap(payload: bytes) -> bytes:
    length = len(payload) + 4
    return struct.pack(">BBH", 3, 0, length) + payload


def x224_cc(dst_ref: int = 0x0000, src_ref: int = 0x1234, neg_rsp: bool = True) -> bytes:
    """X.224 Connection Confirm, como o Windows envia.

    DST-REF ecoa o SRC-REF do cliente; SRC-REF é a referência do próprio
    servidor (0x1234). O RDP_NEG_RSP (selecionando PROTOCOL_RDP) só vai
    quando o pedido trouxe RDP_NEG_REQ (MS-RDPBCGR 2.2.1.2); um pedido
    legado recebe o confirm legado de 11 bytes — exatamente o que o
    ms12_020_check testa. LI conta o cabeçalho depois dele: 6, ou 14 com
    RDP_NEG_RSP.
    """
    body = struct.pack(">BHHB", 0xD0, dst_ref, src_ref, 0x00)
    if neg_rsp:
        body += struct.pack("<BBHI", 0x02, 0x00, 0x0008, 0x00000000)
    return tpkt_wrap(struct.pack(">B", len(body)) + body)


def x224_data_wrap(payload: bytes) -> bytes:
    dt = b'\x02\xf0\x80'
    return tpkt_wrap(dt + payload)


def build_mcs_connect_response(static_channels: int = 0) -> bytes:
    """MCS Connect Response (GCC Conference Create Response).

    Os tamanhos dos campos BER/PER não mudam com o número de canais nem
    com o padding da chave (comprimentos >= 0x100 já usam a forma longa),
    e isso importa: o Metasploit lê os blocos de dados do servidor a
    partir do offset fixo 0x49 do pacote.
    """
    # SC_CORE
    sc_core = struct.pack("<H", 0x0C01)
    sc_core += struct.pack("<H", 16)
    sc_core += struct.pack("<I", 0x00080004)
    sc_core += struct.pack("<I", 0x00000000)
    sc_core += struct.pack("<I", 0x00000001)

    # SC_NET: canal de I/O + um ID por canal estático pedido no CS_NET do
    # cliente, numerados a partir de 1004 na ordem do cliente
    # (MS-RDPBCGR 2.2.1.4.4); padding para múltiplo de 4 bytes.
    ids = [MCS_FIRST_STATIC_CHANNEL + i for i in range(static_channels)]
    sc_net_body = struct.pack("<HH", MCS_IO_CHANNEL, len(ids))
    sc_net_body += b"".join(struct.pack("<H", c) for c in ids)
    if len(ids) % 2:
        sc_net_body += b"\x00\x00"
    sc_net = struct.pack("<HH", 0x0C03, 4 + len(sc_net_body)) + sc_net_body

    # SC_SECURITY with RSA cert (proprietary certificate, chave de 512 bits).
    # MS-RDPBCGR 2.2.1.4.3.1.1.1: keylen = bytes do módulo + 8 bytes de
    # padding zerado (72 para 512 bits). Sem o padding, os clientes leem uma
    # chave de 448 bits e o rdpscan aborta ("Bad server public key size").
    key_len = 64
    modulus = bytes(range(1, key_len + 1)) + b"\x00" * 8
    pubkey_blob = b'RSA1'
    pubkey_blob += struct.pack("<I", key_len + 8)
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


# ------------------------------------------------------------
# Sequência de conexão RDP após o Security Exchange (MS-RDPBCGR 1.3.1.1):
# licença -> Demand Active -> finalização -> primeiras atualizações de tela.
# Os PDUs do servidor vão sem SEC_ENCRYPT (cabeçalho de segurança com
# flags 0): os clientes só decifram o que traz SEC_ENCRYPT, e o decoy
# nunca precisa decifrar o que o cliente envia — basta o tipo do PDU (flags
# do cabeçalho de segurança) e o canal MCS em que ele chega.
# ------------------------------------------------------------

def per_length(n: int) -> bytes:
    """Determinante de comprimento PER como o MCS usa (1 byte abaixo de 0x80)."""
    return bytes([n]) if n < 0x80 else bytes([0x80 | (n >> 8), n & 0xFF])


def mcs_send_data_indication(payload: bytes, channel_id: int = MCS_IO_CHANNEL) -> bytes:
    """MCS Send Data Indication (servidor -> cliente). O initiator vai
    codificado em PER como userId - 1001 (o servidor é o usuário 1002)."""
    hdr = struct.pack(">BHHB", 0x68, MCS_SERVER_CHANNEL - 1001, channel_id, 0x70)
    return x224_data_wrap(hdr + per_length(len(payload)) + payload)


def build_license_valid_client() -> bytes:
    """Server License Error PDU - Valid Client (MS-RDPBCGR 2.2.1.12.1.1):
    o licenciamento é dispensado. 34 bytes no fio, sem criptografia e com
    SEC_LICENSE_PKT, como o Windows envia; o Metasploit exige
    STATUS_VALID_CLIENT (0x7)."""
    msg = struct.pack("<II", 0x00000007, 0x00000002)     # STATUS_VALID_CLIENT, ST_NO_TRANSITION
    msg += struct.pack("<HH", 0x0004, 0)                  # bbErrorInfo: BB_ERROR_BLOB vazio
    preamble = struct.pack("<BBH", 0xFF, 0x03, 4 + len(msg))  # ERROR_ALERT, PREAMBLE_VERSION_3_0
    return mcs_send_data_indication(struct.pack("<HH", SEC_LICENSE_PKT, 0) + preamble + msg)


def _share_control(pdu_type: int, body: bytes) -> bytes:
    """Share Control Header (totalLength, pduType | TS_PROTOCOL_VERSION, pduSource)."""
    return struct.pack("<HHH", 6 + len(body), pdu_type | 0x10, MCS_SERVER_CHANNEL) + body


def _capset(cap_type: int, body: bytes) -> bytes:
    return struct.pack("<HH", cap_type, 4 + len(body)) + body


def build_demand_active(share_id: int = SHARE_ID) -> bytes:
    """Server Demand Active PDU (MS-RDPBCGR 2.2.1.13.1) com as capability
    sets que um servidor Windows anuncia. Os clientes só interpretam General
    e Bitmap; as demais têm o tamanho e o layout corretos e são puladas."""
    order_support = bytearray(32)
    for i in (0, 1, 2, 3, 4, 8, 9, 10, 11, 15, 16, 17, 18, 22, 24, 27):
        order_support[i] = 1
    caps = [
        _capset(0x0001, struct.pack("<HHHHHHHHHBB",          # General
                                    1, 3, 0x0200, 0, 0, 0x041D, 0, 0, 0, 1, 1)),
        _capset(0x0002, struct.pack("<HHHHHHHHHBBHH",        # Bitmap
                                    16, 1, 1, 1, 1024, 768, 0, 1, 1, 0, 0, 1, 0)),
        _capset(0x0003, b"\x00" * 16 + struct.pack("<IHHHHHH", 0, 1, 20, 0, 1, 0, 0x0022)  # Order
                + bytes(order_support)
                + struct.pack("<HHIIHHHH", 0x06A1, 0, 0, 480 * 480, 0, 0, 0, 0)),
        _capset(0x0008, struct.pack("<HHH", 1, 25, 25)),         # Pointer
        _capset(0x000D, struct.pack("<HHIIII", 0x0035, 0, 0, 0, 0, 0) + b"\x00" * 64),  # Input
        _capset(0x0014, struct.pack("<II", 0, 1600)),            # Virtual Channel
        _capset(0x0009, struct.pack("<HH", MCS_SERVER_CHANNEL, 0)),  # Share
        _capset(0x000E, struct.pack("<HH", 1, 0)),               # Font
        _capset(0x000A, struct.pack("<HH", 6, 0)),               # Color Cache
    ]
    combined = struct.pack("<HH", len(caps), 0) + b"".join(caps)
    body = struct.pack("<IHH", share_id, 4, len(combined)) + b"RDP\x00" + combined
    body += struct.pack("<I", 0)                                  # sessionId
    return mcs_send_data_indication(struct.pack("<HH", 0, 0) + _share_control(0x1, body))


def build_share_data_pdu(pdu_type2: int, body: bytes, share_id: int = SHARE_ID) -> bytes:
    """Data PDU (slow-path) no canal de I/O, sem criptografia."""
    hdr = struct.pack("<IBBHBBH", share_id, 0, 1, len(body) + 4, pdu_type2, 0, 0)
    return mcs_send_data_indication(struct.pack("<HH", 0, 0) + _share_control(0x7, hdr + body))


def build_server_finalization(user_id: int) -> list[bytes]:
    """Synchronize, Control (Cooperate), Control (Granted Control) e Font Map
    — o que o servidor envia na finalização da conexão (MS-RDPBCGR 1.3.1.1)."""
    return [
        build_share_data_pdu(0x1F, struct.pack("<HH", 1, user_id)),                     # Synchronize
        build_share_data_pdu(0x14, struct.pack("<HHI", 0x0004, 0, 0)),                  # Cooperate
        build_share_data_pdu(0x14, struct.pack("<HHI", 0x0002, user_id, MCS_SERVER_CHANNEL)),  # Granted
        build_share_data_pdu(0x28, struct.pack("<HHHH", 0, 0, 0x0003, 4)),              # Font Map
    ]


def build_orders_update_memblt() -> bytes:
    """Primeira atualização de tela: um Orders Update com uma ordem MEMBLT
    (sem campos). É o servidor "começando a desenhar"; o rdpscan só envia a
    sonda MS_T120 depois de receber ordens de desenho."""
    memblt = struct.pack("<BBH", 0x09, 0x0D, 0x0000)   # TS_STANDARD|TS_TYPE_CHANGE, MEMBLT, fieldFlags 0
    body = struct.pack("<HHHH", 0x0000, 0, 1, 0) + memblt  # UPDATETYPE_ORDERS, 1 ordem
    return build_share_data_pdu(0x02, body)


def build_disconnect_provider_ultimatum() -> bytes:
    """MCS Disconnect Provider Ultimatum: 03 00 00 09 02 f0 80 21 80."""
    return x224_data_wrap(b"\x21\x80")


def is_disconnect_provider_ultimatum(pdu: bytes) -> bool:
    return len(pdu) >= 9 and pdu[0] == 0x03 and pdu[4:7] == b"\x02\xf0\x80" and pdu[7] >> 2 == 8


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


def client_data_offset(data: bytes) -> int:
    """Início dos blocos de dados do cliente (CS_CORE, CS_SECURITY,
    CS_NET...) num MCS Connect Initial: logo depois da chave H.221 "Duca" e
    do seu comprimento PER. Procurar direto pelos bytes 01 c0 (tipo do
    CS_CORE) acha antes um "00 01 c0 00" que faz parte do próprio cabeçalho
    GCC, logo antes de "Duca" — e todo o parse sai desalinhado (hostnames
    ilegíveis, canais não encontrados). Retorna -1 se não achar."""
    k = data.find(b"Duca")
    if k >= 0 and k + 6 <= len(data):
        off = k + 4 + (2 if data[k + 4] & 0x80 else 1)
        if data[off:off + 2] == struct.pack("<H", 0xC001):
            return off
    return data.find(struct.pack("<H", 0xC001))


def parse_mcs_connect_initial(data: bytes) -> dict:
    info = {}
    try:
        raw = data
        pos = client_data_offset(raw)
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


def is_x224_connection_request(data: bytes) -> bool:
    """TPKT + X.224 Connection Request (código 0xE0)."""
    return len(data) >= 11 and data[0] == 0x03 and (data[5] & 0xF0) == 0xE0


def is_mcs_connect_initial(data: bytes) -> bool:
    """TPKT + X.224 Data TPDU + MCS Connect-Initial (BER 7F 65). Qualquer
    outra coisa depois do Connection Confirm — um TLS ClientHello, por
    exemplo, de um cliente que pediu SSL quando o servidor selecionou
    PROTOCOL_RDP — não é a stage 3."""
    return (len(data) >= 9 and data[0] == 0x03 and data[4:7] == b"\x02\xf0\x80"
            and data[7:9] == b"\x7f\x65")


def parse_client_static_channels(data: bytes) -> list[str]:
    """Nomes dos canais virtuais estáticos do CS_NET do Connect Initial, na
    ordem do cliente — o servidor os numera a partir de 1004 nessa ordem."""
    try:
        pos = client_data_offset(data)                   # CS_CORE abre os blocos
        while 0 <= pos and pos + 4 <= len(data):
            btype, blen = struct.unpack("<HH", data[pos:pos + 4])
            if blen < 4:
                break
            if btype == 0xC003:                          # CS_NET
                count = struct.unpack("<I", data[pos + 4:pos + 8])[0]
                names = []
                for i in range(min(count, 31)):
                    raw = data[pos + 8 + 12 * i:pos + 16 + 12 * i]
                    names.append(raw.split(b"\x00", 1)[0].decode("ascii", "replace"))
                return names
            pos += blen
    except (IndexError, struct.error):
        pass
    return []


def parse_mcs_send_data(data: bytes) -> tuple[int, int, bytes]:
    """(initiator, channel_id, user data) de um MCS Send Data Request."""
    try:
        initiator, channel_id = struct.unpack(">HH", data[8:12])
        off = 13
        if data[off] & 0x80:
            off += 1
        return initiator, channel_id, data[off + 1:]
    except (IndexError, struct.error):
        return 0, 0, b""


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
    da CVE simulada (ver docstring do módulo).

    Eventos entregues a `matches_variant()` / `handle_variant_stages()`:
      "attach_user"  — a cada Attach User Request (context: attached_user_ids)
      "channel_join" — a cada Channel Join Request (context: attached_user_ids,
                       initiator, channel_id, channel_name)
      "channel_data" — dados num canal virtual estático (context: channel_id,
                       channel_name), depois da sequência de conexão
    """

    _listener_cls = _RDPPortListener

    def matches_variant(self, event: str, context: dict) -> bool:
        """Decide se esta variante deve tratar o resto da conexão a partir
        deste evento. A família consulta as variantes não-default a cada
        Attach User e no primeiro Channel Join; se nenhuma reconhecer o
        Channel Join, a variante default assume."""
        raise NotImplementedError

    def handle_variant_stages(self, handler: "RDPConnectionHandler",
                               event: str, data: bytes, context: dict) -> Optional[bytes]:
        """Trata os eventos MCS a partir do ponto de divergência —
        aqui vive a lógica específica da CVE (stages 4+)."""
        raise NotImplementedError


class RDPConnectionHandler:
    """Gerencia uma conexão RDP individual, compartilhada por todas as
    variantes registradas na porta. Trata as stages 1-3 uma única vez,
    resolve dinamicamente qual variante (CVE) trata o resto da conexão, e
    conduz a sequência de conexão RDP (Security Exchange, licença, Demand
    Active, finalização) até o ponto em que o scanner envia sua sonda."""

    MAX_PDUS = 300
    # Quanto o Connect Response espera por um PDU seguinte do cliente (ver _hold).
    CONNECT_RESPONSE_HOLD = 0.1

    def __init__(self, listener: _RDPPortListener, sock: socket.socket, addr: tuple):
        self.listener = listener
        self.sock = sock
        self.ip = addr[0]
        self.port = addr[1]
        self.user_id_counter = 1000
        self.attached_user_ids: list[int] = []
        self.channels_joined: list[int] = []
        self.static_channels: dict[int, str] = {}     # MCS channel id -> nome no CS_NET
        self.tracker: Optional[SCTracker] = None
        self._pending_stages: list[tuple[int, str, dict]] = []
        self._resolved: Optional[RDPFamilyDriver] = None
        self._rxbuf = b""
        self._session_state = "mcs"                   # mcs -> secured -> demand_sent -> active
        self._held = b""                              # resposta segurada (ver _hold)
        self._hold_deadline = 0.0

    def handle(self) -> None:
        logger.info(f"🎯 Nova conexão RDP: {self.ip}:{self.port}")
        try:
            self.sock.settimeout(30)

            # ═══ B1: X.224 Connection Request ═══
            data = self._recv()
            if not data:
                return
            if not is_x224_connection_request(data):
                logger.info(f"❔ [{self.ip}:{self.port}] Não é um X.224 Connection Request "
                            f"({data[:8].hex()}) — encerrando")
                return
            cr_info = parse_x224_cr(data)
            negotiated = "requested_protocols" in cr_info
            self._pending_stages.append((1, "X.224 Connection Request", cr_info))
            logger.info(f"🔍 [{self.ip}:{self.port}] X.224 CR: cookie={cr_info.get('cookie', 'none')}")
            self._out(x224_cc(dst_ref=cr_info.get("src_ref", 0), neg_rsp=negotiated))

            # ═══ B2: Security Negotiation (sintética — sem troca de dados) ═══
            self._pending_stages.append((2, "Security Negotiation", {
                "selected_protocol": "PROTOCOL_RDP (0x00000000)",
                "nla_required": False,
                "negotiation": "RDP_NEG_RSP" if negotiated else "legacy (pedido sem RDP_NEG_REQ)",
            }))
            logger.info(f"🔓 [{self.ip}:{self.port}] Security: RDP nativo (sem NLA)")

            # ═══ B3: MCS Connect Initial ═══
            data = self._recv()
            if not data:
                return
            if not is_mcs_connect_initial(data):
                logger.info(f"❔ [{self.ip}:{self.port}] Esperava MCS Connect Initial, chegou "
                            f"{data[:8].hex()} — encerrando sem creditar a stage 3")
                return
            mcs_info = parse_mcs_connect_initial(data)
            names = parse_client_static_channels(data)
            self.static_channels = {MCS_FIRST_STATIC_CHANNEL + i: n for i, n in enumerate(names)}
            mcs_info["static_channels"] = names
            self._pending_stages.append((3, "MCS Connect Initial", mcs_info))
            logger.info(f"🕵️ [{self.ip}:{self.port}] MCS: host='{mcs_info.get('client_hostname','')}' "
                        f"canais={names}")
            self._hold(build_mcs_connect_response(len(names)))

            # ═══ Domain / Attach User / Channel Join / sessão — dispatch dinâmico ═══
            for _ in range(self.MAX_PDUS):
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
                    self._out(build_mcs_attach_confirm(new_id))
                    context = {"attached_user_ids": list(self.attached_user_ids)}
                    if self._resolved is None:
                        variant = self._match_variant("attach_user", context)
                        if variant is not None:
                            self._resolve(variant)
                    if self._resolved is not None:
                        self._send(self._resolved.handle_variant_stages(self, "attach_user", data, context))

                elif pdu_type == "channel_join":
                    initiator, channel_id = extract_channel_join_fields(data)
                    self.channels_joined.append(channel_id)
                    context = {
                        "attached_user_ids": list(self.attached_user_ids),
                        "initiator": initiator,
                        "channel_id": channel_id,
                        "channel_name": self.static_channels.get(channel_id, ""),
                    }
                    if self._resolved is None:
                        self._resolve(self._match_variant("channel_join", context)
                                      or self.listener.effective_default_variant())
                    self._send(self._resolved.handle_variant_stages(self, "channel_join", data, context))

                elif pdu_type == "send_data":
                    if not self._handle_send_data(data):
                        break

                elif self._session_state == "active":
                    continue          # ex.: input fast-path, já com a sessão estabelecida

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

    # ---------------------------------------------------------- sessão RDP

    def _handle_send_data(self, data: bytes) -> bool:
        """Um MCS Send Data Request. Retorna False quando a conexão termina."""
        _initiator, channel_id, payload = parse_mcs_send_data(data)
        if channel_id == MCS_IO_CHANNEL:
            self._handle_io_pdu(payload)
            return True

        name = self.static_channels.get(channel_id)
        logger.info(f"📨 [{self.ip}:{self.port}] Dados no canal virtual {name or '?'} "
                    f"({channel_id}): {len(payload)} bytes")
        if self._resolved is None or name is None:
            return True
        context = {"channel_id": channel_id, "channel_name": name}
        response = self._resolved.handle_variant_stages(self, "channel_data", data, context)
        if response:
            self._out(response)
            if is_disconnect_provider_ultimatum(response):
                self._graceful_close()
                return False
        return True

    def _handle_io_pdu(self, payload: bytes) -> None:
        """PDUs no canal de I/O, reconhecidos pelas flags do cabeçalho de
        segurança (o conteúdo vem cifrado e não precisa ser lido)."""
        flags = struct.unpack("<H", payload[:2])[0] if len(payload) >= 2 else 0
        if flags & SEC_EXCHANGE_PKT:
            logger.info(f"🔐 [{self.ip}:{self.port}] Security Exchange PDU (client random cifrado)")
            self._session_state = "secured"
        elif flags & SEC_INFO_PKT:
            logger.info(f"🪪 [{self.ip}:{self.port}] Client Info PDU -> licença (valid client) + Demand Active")
            self._out(build_license_valid_client() + build_demand_active())
            self._session_state = "demand_sent"
        elif self._session_state == "demand_sent":
            user = self.attached_user_ids[0] if self.attached_user_ids else MCS_SERVER_CHANNEL
            logger.info(f"🖥️ [{self.ip}:{self.port}] Confirm Active -> finalização + 1ª atualização de tela")
            self._out(b"".join(build_server_finalization(user)) + build_orders_update_memblt())
            self._session_state = "active"

    def _graceful_close(self) -> None:
        """Depois do Disconnect Provider Ultimatum: fecha só o lado de envio e
        drena o que o cliente ainda mandar. Fechar com dados não lidos faz o
        kernel responder RST, e o RST pode descartar o Ultimatum no cliente
        antes de ele ser lido."""
        try:
            self.sock.shutdown(socket.SHUT_WR)
            self.sock.settimeout(3)
            while self.sock.recv(8192):
                pass
        except OSError:
            pass

    # ---------------------------------------------------------- utilitários

    def _send(self, response: Optional[bytes]) -> None:
        if response:
            self._out(response)

    def _out(self, data: bytes) -> None:
        """Envia uma resposta — junto com a resposta segurada, se houver."""
        if self._held:
            data, self._held = self._held + data, b""
        if data:
            self.sock.sendall(data)

    def _hold(self, data: bytes) -> None:
        """Segura o Connect Response por até CONNECT_RESPONSE_HOLD segundos.

        Se o cliente já mandou o PDU seguinte sem esperar (o ms12_020_check
        envia Connect Initial e Attach User Request em sequência), a resposta
        a esse PDU sai no MESMO envio que o Connect Response. O módulo lê uma
        resposta por pedido e pega o user id dos bytes 9-10 da primeira
        leitura; com as duas respostas juntas, as leituras seguintes ficam
        alinhadas e ele lê o Channel Join Confirm do qual tira o veredito.
        Com as respostas separadas ele ficava uma resposta atrás e concluía
        "Not vulnerable" (29 de 30 execuções). Clientes que esperam o Connect
        Response (mstsc, rdesktop, nmap, o scanner de BlueKeep) o recebem
        quando a janela expira. TCP_QUICKACK faz o ACK do Connect Initial
        sair na hora, para o Nagle do cliente liberar o próximo PDU já.
        """
        self._held = data
        self._hold_deadline = time.monotonic() + self.CONNECT_RESPONSE_HOLD
        if hasattr(socket, "TCP_QUICKACK"):
            try:
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
            except OSError:
                pass

    def _recv(self) -> Optional[bytes]:
        """Exatamente um PDU TPKT (comprimento RFC 1006), como quer que o TCP
        o tenha cortado ou juntado.

        Clientes enviam Erect Domain e Attach User Request em sequência;
        quando os dois chegavam no mesmo recv(), eram tratados como um PDU
        só e o Attach User Request se perdia, travando o cliente até o
        timeout dele (dependente de tempo: 24/30 execuções do rdpscan, 1/30
        do msf). Bytes que não são TPKT (um TLS ClientHello, input
        fast-path) são devolvidos como chegaram.
        """
        buf = self._rxbuf
        try:
            while True:
                if buf and buf[0] != 0x03:
                    self._rxbuf = b""
                    return buf
                if len(buf) >= 4:
                    n = struct.unpack(">H", buf[2:4])[0]
                    if n < 4:
                        self._rxbuf = b""
                        return buf
                    if len(buf) >= n:
                        self._rxbuf = buf[n:]
                        return buf[:n]
                if self._held:
                    wait = max(0.0, self._hold_deadline - time.monotonic())
                    readable, _, _ = select.select([self.sock], [], [], wait)
                    if not readable:
                        self._out(b"")          # janela expirou: envia o que estava segurado
                chunk = self.sock.recv(8192)
                if not chunk:
                    return None
                buf += chunk
        except (socket.timeout, ConnectionResetError, OSError):
            return None

    def _match_variant(self, event: str, context: dict) -> Optional[RDPFamilyDriver]:
        for variant in self.listener.variants:
            if not variant.is_default_variant() and variant.matches_variant(event, context):
                return variant
        return None

    def _resolve(self, variant: RDPFamilyDriver) -> None:
        """Fixa a variante e abre a sessão num tracker só desta conexão."""
        self._resolved = variant
        self.tracker = variant._tracker.fork()
        self.tracker.new_session(source_ip=self.ip, source_port=self.port)
        for n, name, d in self._pending_stages:
            self.tracker.complete_stage(n, name, source_ip=self.ip, data=d)
        logger.info(f"➡️  [{self.ip}:{self.port}] Conexão resolvida para variante: "
                    f"{variant.get_metadata().name}")

    def _finalize(self) -> None:
        if self._resolved is not None:
            tracker = self.tracker
        elif self._pending_stages:
            # Encerrada antes de qualquer variante poder ser distinguida: só
            # o tronco foi exercitado, então o registro vai para a família
            # (RDP-Recon), não para a variante default.
            tracker = self.listener.unresolved_tracker()
            tracker.new_session(source_ip=self.ip, source_port=self.port)
            for n, name, d in self._pending_stages:
                tracker.complete_stage(n, name, source_ip=self.ip, data=d)
        else:
            return

        if tracker is not None and len(tracker._completed) > 0:
            # α = 1: sucesso só quando o scanner passou pela troca da qual tira
            # o veredito (stage N). Em 4/5 ele ainda não decidiu.
            tracker.finalize_session(
                deception_success=(len(tracker._completed) == tracker.total_stages))
            tracker.print_status()
