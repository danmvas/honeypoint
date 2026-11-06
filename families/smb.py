#!/usr/bin/env python3
"""
Família SMB1-Recon — base compartilhada para drivers de honeypoint que
simulam CVEs cujo reconhecimento SMBv1 começa com a mesma sequência:

  1. Negotiate Protocol
  2. Session Setup
  3. Tree Connect IPC$

Um driver desta família (ex: EternalBlue, MS08-067) herda de
`SMBFamilyDriver` e implementa apenas o ponto em que diverge de outras
CVEs da mesma família — a partir do primeiro comando SMB recebido
depois do Tree Connect.

Como o dispatch dinâmico funciona:
  - Todas as variantes registradas numa porta compartilham um único
    `_SMBPortListener` (só uma pode de fato dar bind()/listen() no
    socket — as demais ficam registradas como candidatas).
  - `SMBConnectionHandler` trata as stages 1-3 uma única vez por
    conexão e bufferiza os eventos.
  - No primeiro comando pós-Tree-Connect, cada variante registrada é
    consultada via `matches_variant()`; a primeira que reconhecer o
    sinal (ex: comando de Trans PeekNamedPipe, ou abertura do pipe
    \\srvsvc) "recebe" a conexão — os eventos bufferizados são
    reproduzidos no SCTracker daquela variante, e o restante da
    conexão é delegado a `handle_variant_stages()`.
  - Se nenhuma variante reconhecer o sinal, a variante marcada como
    `is_default_variant()` (hoje: EternalBlue) trata a conexão — igual
    ao comportamento genérico que já existia antes desta família ser
    extraída.

Este módulo é específico de SMB — por isso vive em families/, não em
framework/ (framework/README.md: o core nunca deve conter lógica de
protocolo) nem em drivers/ (não é uma CVE específica, é o tronco
compartilhado por várias).
"""

import datetime
import logging
import socket
import struct
from typing import Optional

from framework.base import DriverMetadata, StageDefinition
from framework.tracker import SCTracker
from framework import family

logger = logging.getLogger("honeypoint.smb_family")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _sh = logging.StreamHandler()
    _sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(_sh)


# ============================================================
# SMB1 PROTOCOL CONSTANTS & HELPERS (compartilhados por toda a família)
# ============================================================

SMB1_HEADER_MAGIC = b'\xffSMB'


def netbios_header(payload_len: int) -> bytes:
    return struct.pack(">B", 0x00) + payload_len.to_bytes(3, byteorder='big')


def build_smb1_header(command: int, status: int = 0, flags: int = 0x98,
                       flags2: int = 0xC853, tid: int = 0, pid: int = 0,
                       uid: int = 0, mid: int = 0) -> bytes:
    header = SMB1_HEADER_MAGIC
    header += struct.pack("<B", command)
    header += struct.pack("<I", status)
    header += struct.pack("<B", flags)
    header += struct.pack("<H", flags2)
    header += b'\x00' * 2
    header += b'\x00' * 8
    header += b'\x00' * 2
    header += struct.pack("<H", tid)
    header += struct.pack("<H", pid)
    header += struct.pack("<H", uid)
    header += struct.pack("<H", mid)
    return header


def parse_dialect_index(data: bytes) -> int:
    try:
        offset = 4 + 32 + 1 + 2
        index = 0
        while offset < len(data):
            if data[offset] != 0x02:
                break
            offset += 1
            null_pos = data.index(0x00, offset)
            dialect = data[offset:null_pos].decode('ascii', errors='ignore')
            if dialect == 'NT LM 0.12':
                return index
            offset = null_pos + 1
            index += 1
    except (ValueError, IndexError):
        pass
    return index


def parse_smb_header(data: bytes) -> dict:
    try:
        h = data[4:]
        if h[:4] != b'\xffSMB':
            return {}
        return {
            "command": f"0x{h[4]:02x}",
            "flags": f"0x{h[9]:02x}",
            "flags2": f"0x{struct.unpack('<H', h[10:12])[0]:04x}",
            "tid": struct.unpack('<H', h[24:26])[0],
            "pid": struct.unpack('<H', h[26:28])[0],
            "uid": struct.unpack('<H', h[28:30])[0],
            "mid": struct.unpack('<H', h[30:32])[0],
        }
    except (IndexError, struct.error):
        return {}


def parse_session_setup(data: bytes) -> dict:
    info = {}
    try:
        smb_start = 4
        body_start = smb_start + 32
        word_count = data[body_start]
        info["word_count"] = word_count

        if word_count == 13:
            words_start = body_start + 1
            oem_pw_len = struct.unpack('<H', data[words_start+14:words_start+16])[0]
            uni_pw_len = struct.unpack('<H', data[words_start+16:words_start+18])[0]
            capabilities = struct.unpack('<I', data[words_start+22:words_start+26])[0]
            info["capabilities"] = f"0x{capabilities:08x}"
            bc_offset = words_start + 26
            str_offset = bc_offset + 2 + oem_pw_len + uni_pw_len
            remaining = data[str_offset:]
            strings = []
            pos = 0
            while pos < len(remaining) and len(strings) < 4:
                null_pos = remaining.find(b'\x00', pos)
                if null_pos == -1:
                    break
                s = remaining[pos:null_pos].decode('ascii', errors='replace')
                if s:
                    strings.append(s)
                pos = null_pos + 1
            field_names = ["account_name", "primary_domain", "native_os", "native_lan_manager"]
            for i, name in enumerate(field_names):
                info[name] = strings[i] if i < len(strings) else ""

        elif word_count == 12:
            words_start = body_start + 1
            security_blob_len = struct.unpack('<H', data[words_start+14:words_start+16])[0]
            bc_offset = words_start + 24
            blob_start = bc_offset + 2
            security_blob = data[blob_start:blob_start+security_blob_len]
            info["auth_type"] = "NTLMSSP/SPNEGO"
            if b'NTLMSSP' in security_blob:
                ntlm_offset = security_blob.index(b'NTLMSSP')
                msg_type = struct.unpack('<I', security_blob[ntlm_offset+8:ntlm_offset+12])[0]
                info["ntlmssp_type"] = msg_type
                if msg_type == 1:
                    flags = struct.unpack('<I', security_blob[ntlm_offset+12:ntlm_offset+16])[0]
                    info["ntlmssp_flags"] = f"0x{flags:08x}"
            str_offset = blob_start + security_blob_len
            remaining = data[str_offset:]
            strings = []
            pos = 0
            while pos < len(remaining) and len(strings) < 2:
                null_pos = remaining.find(b'\x00', pos)
                if null_pos == -1:
                    break
                s = remaining[pos:null_pos].decode('ascii', errors='replace')
                if s:
                    strings.append(s)
                pos = null_pos + 1
            if len(strings) >= 1:
                info["native_os"] = strings[0]
            if len(strings) >= 2:
                info["native_lan_manager"] = strings[1]
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


def parse_tree_connect(data: bytes) -> dict:
    info = {}
    try:
        body_start = 4 + 32
        word_count = data[body_start]
        words_start = body_start + 1
        pw_len = struct.unpack('<H', data[words_start+6:words_start+8])[0]
        bc_offset = words_start + (word_count * 2)
        path_start = bc_offset + 2 + pw_len
        remaining = data[path_start:]
        double_null = remaining.find(b'\x00\x00')
        if double_null > 0 and double_null < 100:
            path_bytes = remaining[:double_null+1]
            try:
                info["share_path"] = path_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
            except Exception:
                info["share_path"] = path_bytes.decode('ascii', errors='replace').rstrip('\x00')
        else:
            null_pos = remaining.find(b'\x00')
            if null_pos > 0:
                info["share_path"] = remaining[:null_pos].decode('ascii', errors='replace')
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


def parse_transaction(data: bytes) -> dict:
    info = {}
    try:
        body_start = 4 + 32
        word_count = data[body_start]
        words_start = body_start + 1
        if word_count >= 14:
            info["setup_count"] = data[words_start+26]
            setup_count = data[words_start+26]
            if setup_count >= 1:
                setup_offset = words_start + 28
                subcommand = struct.unpack('<H', data[setup_offset:setup_offset+2])[0]
                info["subcommand"] = f"0x{subcommand:04x}"
                subcmd_names = {
                    0x0023: "PeekNamedPipe", 0x0026: "TransactNmPipe",
                    0x0053: "WaitNamedPipe", 0x0001: "SetNamedPipeState",
                }
                info["subcommand_name"] = subcmd_names.get(subcommand, "Unknown")
            bc_offset = words_start + (word_count * 2)
            byte_count = struct.unpack('<H', data[bc_offset:bc_offset+2])[0]
            name_start = bc_offset + 2
            remaining = data[name_start:name_start+byte_count]
            null_pos = remaining.find(b'\x00')
            if null_pos > 0:
                info["pipe_name"] = remaining[:null_pos].decode('ascii', errors='replace')
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


def parse_nt_create_andx(data: bytes) -> dict:
    """Extrai o path solicitado num NT_CREATE_ANDX (comando 0xA2) —
    usado por variantes que verificam abertura de pipes específicos
    (ex: \\srvsvc, \\browser)."""
    info = {}
    try:
        body_start = 4 + 32
        word_count = data[body_start]
        info["word_count"] = word_count
        words_start = body_start + 1
        name_len = struct.unpack('<H', data[words_start+5:words_start+7])[0]
        info["name_length"] = name_len
        bc_offset = words_start + (word_count * 2)
        name_start = bc_offset + 2
        if name_start % 2 != 0:
            name_start += 1  # alinhamento UTF-16LE
        raw_name = data[name_start:name_start + name_len]
        try:
            path = raw_name.decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            path = raw_name.decode('ascii', errors='replace')
        info["path"] = path
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


def find_dcerpc_pdu(data: bytes) -> Optional[bytes]:
    """Localiza um PDU DCE/RPC embutido num pacote SMB (transportado via
    Transaction/WriteAndX — a forma exata varia por cliente). Procura a
    assinatura do cabeçalho comum DCE/RPC (versão 5.0 + tipo de pacote
    plausível) em vez de assumir um comando SMB específico."""
    limit = len(data) - 16  # último índice válido para um cabeçalho de 16 bytes
    idx = 0
    while idx <= limit:
        if data[idx] == 0x05 and data[idx + 1] == 0x00 and data[idx + 2] in (0x00, 0x0B, 0x02, 0x0C, 0x03):
            return data[idx:]
        idx += 1
    return None


def parse_dcerpc_pdu(pdu: bytes) -> dict:
    info = {}
    try:
        info["version"] = pdu[0]
        info["packet_type"] = pdu[2]
        info["frag_length"] = struct.unpack('<H', pdu[8:10])[0]
        info["call_id"] = struct.unpack('<I', pdu[12:16])[0]
        if info["packet_type"] == 0x00 and len(pdu) >= 24:
            info["opnum"] = struct.unpack('<H', pdu[22:24])[0]
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    return info


def build_negotiate_response(dialect_index: int = 3) -> bytes:
    smb_header = build_smb1_header(command=0x72, status=0, flags=0x98, flags2=0xC053)
    body = b''
    body += struct.pack("<B", 17)
    body += struct.pack("<H", dialect_index)
    body += struct.pack("<B", 0x03)
    body += struct.pack("<H", 50)
    body += struct.pack("<H", 1)
    body += struct.pack("<I", 16644)
    body += struct.pack("<I", 65536)
    body += struct.pack("<I", 0)
    body += struct.pack("<I", 0x0000F3F7)
    now = datetime.datetime.now(datetime.timezone.utc)
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    filetime = int((now - epoch).total_seconds() * 10_000_000)
    body += struct.pack("<Q", filetime)
    body += struct.pack("<h", 180)
    body += struct.pack("<B", 8)
    encryption_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef'
    domain_name = 'WORKGROUP\x00'.encode('utf-16-le')
    server_name = 'WIN7-PC\x00'.encode('utf-16-le')
    payload = encryption_key + domain_name + server_name
    body += struct.pack("<H", len(payload))
    body += payload
    smb_packet = smb_header + body
    return netbios_header(len(smb_packet)) + smb_packet


def build_session_setup_response(uid: int = 100) -> bytes:
    smb_header = build_smb1_header(command=0x73, status=0, flags=0x98, flags2=0xC053, uid=uid)
    body = b''
    body += struct.pack("<B", 3)
    body += struct.pack("<B", 0)
    body += struct.pack("<B", 0)
    body += struct.pack("<H", 0)
    body += struct.pack("<H", 1)
    native_os = 'Windows 7 Professional 7601 Service Pack 1\x00'.encode('utf-16-le')
    native_lm = 'Windows 7 Professional 6.1\x00'.encode('utf-16-le')
    primary_domain = 'WORKGROUP\x00'.encode('utf-16-le')
    byte_data = native_os + native_lm + primary_domain
    body += struct.pack("<H", len(byte_data))
    body += byte_data
    smb_packet = smb_header + body
    return netbios_header(len(smb_packet)) + smb_packet


def build_nt_create_andx_response(fid: int, tid: int = 0, uid: int = 0) -> bytes:
    """Resposta de abertura de pipe bem-sucedida (FileTypeMessageModePipe)."""
    body = b''
    body += struct.pack("<B", 0xFF)          # AndXCommand = none
    body += struct.pack("<B", 0)             # AndXReserved
    body += struct.pack("<H", 0)             # AndXOffset
    body += struct.pack("<B", 0)             # OplockLevel
    body += struct.pack("<H", fid & 0xFFFF)  # FID
    body += struct.pack("<I", 1)             # CreateAction (FILE_OPENED)
    body += struct.pack("<Q", 0)             # LastWriteTime
    body += struct.pack("<Q", 0)             # EndOfFile
    body += struct.pack("<H", 2)             # FileType = FileTypeMessageModePipe
    body += struct.pack("<H", 0x00FF)        # IPCState (pipe padrão)
    body += struct.pack("<B", 0)             # IsDirectory
    if len(body) % 2:
        body += b'\x00'
    word_count = len(body) // 2

    smb_header = build_smb1_header(command=0xA2, status=0, tid=tid, uid=uid)
    packet_body = struct.pack("<B", word_count) + body + struct.pack("<H", 0)
    smb_packet = smb_header + packet_body
    return netbios_header(len(smb_packet)) + smb_packet


def build_dcerpc_bind_ack(call_id: int) -> bytes:
    body = struct.pack("<H", 4280)    # max_xmit_frag
    body += struct.pack("<H", 4280)   # max_recv_frag
    body += struct.pack("<I", 0x000053F0)  # assoc_group_id
    body += b'\x00\x00'                # secondary address (vazio)
    if len(body) % 4:
        body += b'\x00' * (4 - (len(body) % 4))
    body += struct.pack("<B", 1)       # num_results
    body += b'\x00' * 3
    body += struct.pack("<H", 0)       # ack_result = acceptance
    body += struct.pack("<H", 0)       # ack_reason
    body += b'\x00' * 16               # transfer_syntax UUID
    body += struct.pack("<I", 0)       # transfer_syntax version

    frag_len = 16 + len(body)
    header = struct.pack("<BBBB", 5, 0, 0x0C, 0x03)  # ver, ver_minor, bind_ack, pfc_flags
    header += b'\x10\x00\x00\x00'                      # packed_drep
    header += struct.pack("<H", frag_len)
    header += struct.pack("<H", 0)                      # auth_length
    header += struct.pack("<I", call_id)
    return header + body


def build_dcerpc_response(call_id: int, stub: bytes) -> bytes:
    body = struct.pack("<I", len(stub))   # alloc_hint
    body += struct.pack("<H", 0)          # context_id
    body += struct.pack("<B", 0)          # cancel_count
    body += struct.pack("<B", 0)          # reserved
    body += stub

    frag_len = 16 + len(body)
    header = struct.pack("<BBBB", 5, 0, 0x02, 0x03)  # ver, ver_minor, response, pfc_flags
    header += b'\x10\x00\x00\x00'
    header += struct.pack("<H", frag_len)
    header += struct.pack("<H", 0)
    header += struct.pack("<I", call_id)
    return header + body


def wrap_dcerpc_in_smb_trans(pdu_bytes: bytes, tid: int = 0, uid: int = 0) -> bytes:
    """Envelopa um PDU DCE/RPC bruto numa resposta SMB1 Transaction
    (TransactNamedPipe) — forma como scanners costumam ler a resposta
    de um bind/chamada RPC feita sobre named pipe. Sem parâmetros
    (ParameterCount=0), só dados."""
    word_count = 10
    header_len = 32
    bytecount_field_end = header_len + 1 + (word_count * 2) + 2
    pad = b'\x00' if bytecount_field_end % 2 else b''
    data_rel_offset = bytecount_field_end + len(pad)

    words = struct.pack("<H", 0)                  # TotalParameterCount
    words += struct.pack("<H", len(pdu_bytes))     # TotalDataCount
    words += struct.pack("<H", 0)                  # Reserved
    words += struct.pack("<H", 0)                  # ParameterCount
    words += struct.pack("<H", 0)                  # ParameterOffset
    words += struct.pack("<H", 0)                  # ParameterDisplacement
    words += struct.pack("<H", len(pdu_bytes))      # DataCount
    words += struct.pack("<H", data_rel_offset)     # DataOffset
    words += struct.pack("<H", 0)                   # DataDisplacement
    words += struct.pack("<B", 0)                   # SetupCount
    words += struct.pack("<B", 0)                   # Reserved2

    byte_area = pad + pdu_bytes
    body = struct.pack("<B", word_count) + words + struct.pack("<H", len(byte_area)) + byte_area

    smb_header = build_smb1_header(command=0x25, status=0, tid=tid, uid=uid)
    smb_packet = smb_header + body
    return netbios_header(len(smb_packet)) + smb_packet


# ============================================================
# STAGES COMPARTILHADAS (1-3) — idênticas em toda a família SMB1-Recon
# ============================================================

SHARED_SMB_STAGES = [
    StageDefinition(1, "SMB Negotiate",
        "Scanner envia Negotiate Protocol Request com lista de dialetos", "SMB"),
    StageDefinition(2, "Session Setup",
        "Scanner inicia Session Setup com NTLMSSP Negotiate", "SMB"),
    StageDefinition(3, "Tree Connect IPC$",
        "Scanner conecta ao share administrativo IPC$", "SMB"),
]


# ============================================================
# BASE DE FAMÍLIA E DISPATCH DINÂMICO
# (a orquestração genérica — registro de variantes, accept loop,
#  compartilhamento de porta — vem de framework.family; aqui só entra
#  o que é específico de SMB: qual ConnectionHandler instanciar)
# ============================================================

class _SMBPortListener(family.PortListener):
    """Listener SMB — só precisa dizer qual ConnectionHandler usar."""

    def _create_handler(self, sock: socket.socket, addr: tuple) -> "SMBConnectionHandler":
        return SMBConnectionHandler(self, sock, addr)


class SMBFamilyDriver(family.FamilyDriver):
    """Base para drivers que simulam CVEs de uma mesma família SMBv1.

    As stages 1-3 são tratadas uma única vez pelo listener compartilhado
    da porta; subclasses implementam apenas o ponto de divergência real
    da CVE simulada.
    """

    _listener_cls = _SMBPortListener

    def matches_variant(self, command: int, parsed: dict) -> bool:
        """Decide, a partir do primeiro comando pós-Tree-Connect, se
        esta variante deve tratar o resto da conexão."""
        raise NotImplementedError

    def handle_variant_stages(self, handler: "SMBConnectionHandler",
                               command: int, data: bytes, parsed: dict) -> Optional[bytes]:
        """Trata os comandos SMB a partir do ponto de divergência —
        aqui vive a lógica específica da CVE (stages 4+)."""
        raise NotImplementedError


class SMBConnectionHandler:
    """Gerencia uma conexão SMB1 individual, compartilhada por todas as
    variantes registradas na porta. Trata as stages 1-3 uma única vez e,
    a partir do primeiro comando pós-Tree-Connect, resolve dinamicamente
    qual variante (CVE) trata o resto da conexão."""

    def __init__(self, listener: _SMBPortListener, sock: socket.socket, addr: tuple):
        self.listener = listener
        self.sock = sock
        self.ip = addr[0]
        self.port = addr[1]
        self.uid = 100
        self.tid = 2048
        self.fid = 0x4000
        self.interaction_count = 0
        self.tracker: Optional[SCTracker] = None
        self._pending_stages: list[tuple[int, str, dict]] = []
        self._resolved: Optional[SMBFamilyDriver] = None
        self._rxbuf = b""

    def handle(self) -> None:
        logger.info(f"🎯 Nova conexão SMB: {self.ip}:{self.port}")
        try:
            self.sock.settimeout(30)
            while True:
                data = self._recv_msg()
                if not data:
                    break
                self.interaction_count += 1
                response = self._process(data)
                if response:
                    self.sock.sendall(response)
                else:
                    break
        except socket.timeout:
            logger.info(f"⏰ [{self.ip}:{self.port}] Timeout após {self.interaction_count} interações")
        except ConnectionResetError:
            logger.info(f"🔌 [{self.ip}:{self.port}] Conexão resetada")
        except Exception as e:
            logger.error(f"❌ [{self.ip}:{self.port}] Erro: {e}")
        finally:
            self.sock.close()
            self._finalize()
            logger.info(f"🔒 [{self.ip}:{self.port}] Encerrada ({self.interaction_count} interações)")

    def _recv_msg(self) -> Optional[bytes]:
        """Exatamente uma mensagem NetBIOS (cabeçalho de 4 bytes + o
        comprimento de 24 bits que ele declara), como quer que o TCP a tenha
        cortado ou juntado. Antes, cada recv(4096) era tratado como uma
        mensagem: duas mensagens no mesmo recv() perdiam a segunda, e uma
        mensagem maior que 4 KiB era truncada. Os scanners SMB1 testados
        esperam cada resposta antes do próximo pedido, por isso isso nunca
        apareceu — mas nada garante. Exceções de socket sobem para handle().
        """
        buf = self._rxbuf
        while True:
            if buf and buf[0] not in (0x00, 0x81, 0x82, 0x83, 0x84, 0x85):
                # não é NetBIOS (ex.: uma sonda HTTP): devolve como chegou, e
                # _process() encerra a conexão como antes
                self._rxbuf = b""
                return buf
            if len(buf) >= 4:
                n = 4 + int.from_bytes(buf[1:4], "big")
                if len(buf) >= n:
                    self._rxbuf = buf[n:]
                    return buf[:n]
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            buf += chunk

    def _process(self, data: bytes) -> Optional[bytes]:
        if len(data) < 8:
            return None
        smb_offset = 4
        if data[smb_offset:smb_offset+4] == b'\xffSMB':
            command = data[smb_offset + 4]
            return self._dispatch(command, data)
        elif data[smb_offset:smb_offset+4] == b'\xfeSMB':
            logger.info(f"🔍 [{self.ip}:{self.port}] SMB2 detectado — forçando SMB1")
            return build_negotiate_response()
        elif data[0] == 0x81:
            logger.info(f"🔍 [{self.ip}:{self.port}] NetBIOS Session Request")
            return b'\x82\x00\x00\x00'
        return None

    def _parse_for_variant(self, command: int, data: bytes) -> dict:
        if command in (0x25, 0x32, 0xA0):
            return parse_transaction(data)
        elif command == 0xA2:
            return parse_nt_create_andx(data)
        return {}

    def _resolve_variant(self, command: int, parsed: dict) -> SMBFamilyDriver:
        for variant in self.listener.variants:
            if not variant.is_default_variant() and variant.matches_variant(command, parsed):
                return variant
        return self.listener.effective_default_variant()

    def _dispatch(self, command: int, data: bytes) -> Optional[bytes]:
        if self._resolved is not None:
            parsed = self._parse_for_variant(command, data)
            return self._resolved.handle_variant_stages(self, command, data, parsed)

        if command == 0x72:  # NEGOTIATE
            idx = parse_dialect_index(data)
            self._pending_stages.append((1, "SMB Negotiate", {"dialect_index": idx}))
            logger.info(f"🔍 [{self.ip}:{self.port}] Dialect index: {idx}")
            return build_negotiate_response(idx)

        elif command == 0x73:  # SESSION_SETUP
            info = parse_session_setup(data)
            self._pending_stages.append((2, "Session Setup", info))
            logger.info(f"🕵️ [{self.ip}:{self.port}] Session Setup: OS='{info.get('native_os','')}'")
            return build_session_setup_response(self.uid)

        elif command == 0x75:  # TREE_CONNECT
            info = parse_tree_connect(data)
            self._pending_stages.append((3, "Tree Connect IPC$", info))
            logger.info(f"🌲 [{self.ip}:{self.port}] Tree Connect: {info.get('share_path', 'unknown')}")
            return self._build_tree_connect_success()

        else:
            parsed = self._parse_for_variant(command, data)
            self._resolved = self._resolve_variant(command, parsed)
            # Um tracker por conexão: o tracker do driver é compartilhado por
            # todas as conexões, e new_session() de uma zeraria a outra.
            self.tracker = self._resolved._tracker.fork()
            self.tracker.new_session(source_ip=self.ip, source_port=self.port)
            for n, name, d in self._pending_stages:
                self.tracker.complete_stage(n, name, source_ip=self.ip, data=d)
            logger.info(f"➡️  [{self.ip}:{self.port}] Conexão resolvida para variante: "
                        f"{self._resolved.get_metadata().name}")
            return self._resolved.handle_variant_stages(self, command, data, parsed)

    def _finalize(self) -> None:
        if self._resolved is not None:
            tracker = self.tracker
        elif self._pending_stages:
            # Encerrada antes de qualquer variante poder ser distinguida: o
            # registro vai para a família (tronco), não para a variante default.
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

    def _build_tree_connect_success(self) -> bytes:
        smb_header = build_smb1_header(command=0x75, status=0, flags=0x98, flags2=0xC053,
                                        tid=self.tid, uid=self.uid)
        body = b''
        body += struct.pack("<B", 3)
        body += struct.pack("<B", 0)
        body += struct.pack("<B", 0)
        body += struct.pack("<H", 0)
        body += struct.pack("<H", 1)
        service = b'IPC\x00'
        native_fs = b'\x00'
        body += struct.pack("<H", len(service) + len(native_fs))
        body += service + native_fs
        smb_packet = smb_header + body
        return netbios_header(len(smb_packet)) + smb_packet

    def build_error_response(self, command: int, status: int) -> bytes:
        smb_header = build_smb1_header(command=command, status=status,
                                        tid=self.tid, uid=self.uid)
        body = struct.pack("<B", 0) + struct.pack("<H", 0)
        smb_packet = smb_header + body
        return netbios_header(len(smb_packet)) + smb_packet
