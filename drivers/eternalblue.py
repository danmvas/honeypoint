#!/usr/bin/env python3
"""
Driver: EternalBlue (CVE-2017-0144 / MS17-010)
===============================================
Honeypoint que simula um servidor SMB vulnerável ao EternalBlue,
enganando o scanner Metasploit auxiliary/scanner/smb/smb_ms17_010.

Stages do reconhecimento:
  E1: SMB Negotiate         — Scanner envia Negotiate Protocol Request
  E2: SMB Session Setup     — Scanner inicia Session Setup (NTLMSSP)
  E3: Tree Connect IPC$     — Scanner conecta ao share IPC$
  E4: PeekNamedPipe         — Scanner envia Trans PeekNamedPipe
  E5: Vuln Check Response   — Scanner recebe STATUS_INSUFF_SERVER_RESOURCES

O sinal comportamental distinguidor é a sequência E3→E4:
IPC$ access seguido de PeekNamedPipe SEM acessar recursos reais.
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
LOG_DIR = "./logs/eternalblue"
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("honeypoint.eternalblue")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(f"{LOG_DIR}/honeypoint.log")
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(sh)

json_logger = logging.getLogger("honeypoint.eternalblue.json")
if not json_logger.handlers:
    json_logger.setLevel(logging.INFO)
    jh = logging.FileHandler(f"{LOG_DIR}/events.jsonl")
    jh.setFormatter(logging.Formatter('%(message)s'))
    json_logger.addHandler(jh)


def log_event(event_type: str, client_ip: str, client_port: int, details: dict):
    ev = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type, "src_ip": client_ip,
        "src_port": client_port, "details": details
    }
    json_logger.info(json.dumps(ev))


# ============================================================
# SMB PROTOCOL CONSTANTS & HELPERS
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
            except:
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


# ============================================================
# DRIVER CLASS
# ============================================================

class EternalBlueDriver(HoneyPointDriver):
    """Driver para simulação de EternalBlue/MS17-010."""

    def __init__(self):
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._tracker: Optional[SCTracker] = None

    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            name="EternalBlue",
            cve="CVE-2017-0144",
            cve_alias="MS17-010",
            protocol="SMB",
            default_port=445,
            scanner_module="auxiliary/scanner/smb/smb_ms17_010",
            scanner_tool="Metasploit Framework",
            description="Simula servidor SMB vulnerável ao EternalBlue",
            stages=[
                StageDefinition(1, "SMB Negotiate",
                    "Scanner envia Negotiate Protocol Request com lista de dialetos", "SMB"),
                StageDefinition(2, "Session Setup",
                    "Scanner inicia Session Setup com NTLMSSP Negotiate", "SMB"),
                StageDefinition(3, "Tree Connect IPC$",
                    "Scanner conecta ao share administrativo IPC$", "SMB"),
                StageDefinition(4, "PeekNamedPipe",
                    "Scanner envia Trans PeekNamedPipe para testar named pipes", "SMB"),
                StageDefinition(5, "Vuln Check",
                    "Scanner recebe STATUS_INSUFF_SERVER_RESOURCES indicando vulnerabilidade", "SMB"),
            ]
        )

    def start(self, port: int, tracker: SCTracker) -> None:
        self._tracker = tracker
        self._running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("0.0.0.0", port))
        self._server_socket.listen(10)
        logger.info(f"🍯 EternalBlue Honeypoint escutando na porta {port}")
        log_event("server_start", "0.0.0.0", port, {"bind_port": port})

        while self._running:
            try:
                self._server_socket.settimeout(1.0)
                try:
                    client_sock, addr = self._server_socket.accept()
                except socket.timeout:
                    continue
                handler = _EBHandler(client_sock, addr, self._tracker)
                t = threading.Thread(target=handler.handle, daemon=True,
                                     name=f"smb-{addr[0]}:{addr[1]}")
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

class _EBHandler:
    """Gerencia uma conexão individual ao honeypoint SMB."""

    def __init__(self, sock: socket.socket, addr: tuple, tracker: SCTracker):
        self.sock = sock
        self.ip = addr[0]
        self.port = addr[1]
        self.tracker = tracker
        self.uid = 100
        self.tid = 2048
        self.interaction_count = 0
        self.raw_data_received = []

    def handle(self):
        logger.info(f"🎯 Nova conexão: {self.ip}:{self.port}")
        log_event("connection_open", self.ip, self.port, {})
        self.tracker.new_session(source_ip=self.ip)

        try:
            self.sock.settimeout(30)
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                self.interaction_count += 1
                self.raw_data_received.append(data.hex())
                logger.info(f"📨 [{self.ip}:{self.port}] Recebido {len(data)} bytes (#{self.interaction_count})")
                log_event("data_received", self.ip, self.port, {
                    "length": len(data), "hex_preview": data[:64].hex(),
                    "interaction": self.interaction_count
                })
                response = self._process_smb(data)
                if response:
                    self.sock.sendall(response)
                    logger.info(f"📤 [{self.ip}:{self.port}] Enviado {len(response)} bytes")
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
            logger.info(f"🔒 [{self.ip}:{self.port}] Encerrada ({self.interaction_count} interações)")
            if len(self.tracker._completed) > 0:
                self.tracker.finalize_session(
                    deception_success=(self.tracker.get_sc() >= 0.8)
                )
                self.tracker.print_status()

    def _process_smb(self, data: bytes) -> bytes | None:
        if len(data) < 8:
            return None
        smb_offset = 4
        if data[smb_offset:smb_offset+4] == b'\xffSMB':
            command = data[smb_offset + 4]
            return self._handle_smb1(command, data)
        elif data[smb_offset:smb_offset+4] == b'\xfeSMB':
            logger.info(f"🔍 [{self.ip}:{self.port}] SMB2 detectado — forçando SMB1")
            return build_negotiate_response()
        elif data[0] == 0x81:
            logger.info(f"🔍 [{self.ip}:{self.port}] NetBIOS Session Request")
            return b'\x82\x00\x00\x00'
        return None

    def _handle_smb1(self, command: int, data: bytes) -> bytes | None:
        command_names = {
            0x72: "NEGOTIATE", 0x73: "SESSION_SETUP", 0x75: "TREE_CONNECT",
            0x25: "TRANSACTION", 0x32: "TRANSACTION2", 0xA0: "NT_TRANSACT",
        }
        cmd_name = command_names.get(command, f"UNKNOWN(0x{command:02x})")
        logger.info(f"🔍 [{self.ip}:{self.port}] SMB1 Command: {cmd_name}")

        if command == 0x72:  # NEGOTIATE
            idx = parse_dialect_index(data)
            header_info = parse_smb_header(data)
            logger.info(f"🔍 [{self.ip}:{self.port}] Dialect index: {idx}")
            self.tracker.complete_stage(1, "SMB Negotiate",
                source_ip=self.ip, data={"dialect_index": idx, "smb_header": header_info})
            log_event("negotiate_details", self.ip, self.port, {"dialect_index": idx})
            return build_negotiate_response(idx)

        elif command == 0x73:  # SESSION_SETUP
            session_info = parse_session_setup(data)
            native_os = session_info.get("native_os", "")
            native_lm = session_info.get("native_lan_manager", "")
            tool_guess = "Unknown"
            if "2195" in native_os or "Windows 2000" in native_os:
                tool_guess = "Metasploit (Ruby Rex)"
            elif "Unix" in native_os or "Samba" in native_lm:
                tool_guess = "Impacket / CrackMapExec"
            elif "Windows 10" in native_os:
                tool_guess = "Windows 10 nativo ou PsExec"
            logger.info(f"🕵️ [{self.ip}:{self.port}] FINGERPRINT: OS='{native_os}' LM='{native_lm}' Tool='{tool_guess}'")
            self.tracker.complete_stage(2, "Session Setup",
                source_ip=self.ip, data={
                    "native_os": native_os, "native_lan_manager": native_lm,
                    "tool_guess": tool_guess, **session_info
                })
            log_event("session_setup_fingerprint", self.ip, self.port, {"tool_guess": tool_guess, **session_info})
            return build_session_setup_response(self.uid)

        elif command == 0x75:  # TREE_CONNECT
            tree_info = parse_tree_connect(data)
            share_path = tree_info.get("share_path", "unknown")
            logger.info(f"🌲 [{self.ip}:{self.port}] Tree Connect: {share_path}")
            self.tracker.complete_stage(3, "Tree Connect IPC$",
                source_ip=self.ip, data={"share_path": share_path})
            log_event("tree_connect_attempt", self.ip, self.port, tree_info)
            return self._build_tree_connect_success()

        elif command in (0x25, 0x32, 0xA0):  # TRANSACTION / TRANSACTION2 / NT_TRANSACT
            trans_info = parse_transaction(data)
            pipe_name = trans_info.get("pipe_name", "")
            subcmd = trans_info.get("subcommand_name", "")
            e4_done = 4 in self.tracker._completed

            if not e4_done and command == 0x25:
                # E4: PeekNamedPipe (vuln check)
                self.tracker.complete_stage(4, "PeekNamedPipe",
                    source_ip=self.ip, data={"pipe_name": pipe_name, "subcommand": subcmd})
                log_event("VULN_CHECK", self.ip, self.port, {
                    "alert": "Scanner verificando vulnerabilidade MS17-010",
                    "pipe_name": pipe_name, "subcommand": subcmd
                })
                logger.warning(f"🔍 [{self.ip}:{self.port}] VULN CHECK: Pipe={pipe_name} SubCmd={subcmd}")
            else:
                # E5: exploit attempt
                self.tracker.complete_stage(5, "Vuln Check Response",
                    source_ip=self.ip, data={
                        "command": cmd_name, "pipe_name": pipe_name,
                        "payload_size": len(data), "payload_hex_preview": data[:128].hex()
                    })
                log_event("EXPLOIT_ATTEMPT", self.ip, self.port, {
                    "alert": "TENTATIVA DE EXPLOIT ETERNALBLUE",
                    "command": cmd_name, "raw_hex": data.hex()
                })
                logger.warning(f"🚨 [{self.ip}:{self.port}] EXPLOIT ATTEMPT! Cmd={cmd_name}")

            return self._build_error_response(command, 0xC0000205)

        else:
            return self._build_error_response(command, 0xC0000002)

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

    def _build_error_response(self, command: int, status: int) -> bytes:
        smb_header = build_smb1_header(command=command, status=status,
                                        tid=self.tid, uid=self.uid)
        body = struct.pack("<B", 0) + struct.pack("<H", 0)
        smb_packet = smb_header + body
        return netbios_header(len(smb_packet)) + smb_packet