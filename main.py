#!/usr/bin/env python3
"""
EternalBlue Honeypoint - SMB Service Simulator
================================================
Simula um serviço SMB (porta 445) vulnerável ao MS17-010 (EternalBlue).
Responde ao SMB Negotiate Protocol com banners realistas de Windows 7/2008 R2.

Uso em HOMELAB apenas - ferramenta de pesquisa acadêmica.
Autor: Honeypoint Research Project
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

# ============================================================
# LOGGING SETUP
# ============================================================
LOG_DIR = "/var/log/honeypoint"
os.makedirs(LOG_DIR, exist_ok=True)

# Logger principal (texto legível)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/honeypoint.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("honeypoint")

# Logger JSON estruturado (para análise posterior)
json_logger = logging.getLogger("honeypoint.json")
json_handler = logging.FileHandler(f"{LOG_DIR}/events.jsonl")
json_handler.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(json_handler)
json_logger.setLevel(logging.INFO)


def log_event(event_type: str, client_ip: str, client_port: int, details: dict):
    """Loga evento em formato JSON Lines para análise."""
    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "src_ip": client_ip,
        "src_port": client_port,
        "details": details
    }
    json_logger.info(json.dumps(event))


# ============================================================
# SMB PROTOCOL CONSTANTS & CRAFTED RESPONSES
# ============================================================

# NetBIOS Session Service header (4 bytes)
# Type: Session Message (0x00), Length: varies
def netbios_header(payload_len: int) -> bytes:
    # NetBIOS Session Service: 1 byte type + 3 bytes length (big-endian)
    return struct.pack(">B", 0x00) + payload_len.to_bytes(3, byteorder='big')


# SMB1 Header (32 bytes)
SMB1_HEADER_MAGIC = b'\xffSMB'

def build_smb1_header(command: int, status: int = 0, flags: int = 0x98,
                       flags2: int = 0xC853, tid: int = 0, pid: int = 0,
                       uid: int = 0, mid: int = 0) -> bytes:
    """Constrói um header SMB1 realista."""
    header = SMB1_HEADER_MAGIC
    header += struct.pack("<B", command)       # Command
    header += struct.pack("<I", status)        # NT Status
    header += struct.pack("<B", flags)         # Flags
    header += struct.pack("<H", flags2)        # Flags2
    header += b'\x00' * 2                      # PID High
    header += b'\x00' * 8                      # Signature
    header += b'\x00' * 2                      # Reserved
    header += struct.pack("<H", tid)           # Tree ID
    header += struct.pack("<H", pid)           # Process ID
    header += struct.pack("<H", uid)           # User ID
    header += struct.pack("<H", mid)           # Multiplex ID
    return header


def parse_dialect_index(data: bytes) -> int:
    """Encontra o índice de 'NT LM 0.12' na lista de dialetos do cliente."""
    try:
        # Pular NetBIOS (4) + SMB header (32) + WordCount (1) + ByteCount (2)
        offset = 4 + 32 + 1 + 2
        index = 0
        while offset < len(data):
            if data[offset] != 0x02:  # Cada dialeto começa com 0x02
                break
            offset += 1
            # Encontrar o null terminator
            null_pos = data.index(0x00, offset)
            dialect = data[offset:null_pos].decode('ascii', errors='ignore')
            if dialect == 'NT LM 0.12':
                return index
            offset = null_pos + 1
            index += 1
    except (ValueError, IndexError):
        pass
    return index  # fallback: último dialeto


def parse_smb_header(data: bytes) -> dict:
    """Extrai campos do SMB header para fingerprinting do cliente."""
    try:
        h = data[4:]  # pular NetBIOS
        if h[:4] != b'\xffSMB':
            return {}
        return {
            "command": f"0x{h[4]:02x}",
            "status": f"0x{struct.unpack('<I', h[5:9])[0]:08x}",
            "flags": f"0x{h[9]:02x}",
            "flags2": f"0x{struct.unpack('<H', h[10:12])[0]:04x}",
            "pid_high": struct.unpack('<H', h[12:14])[0],
            "signature": h[14:22].hex(),
            "tid": struct.unpack('<H', h[24:26])[0],
            "pid": struct.unpack('<H', h[26:28])[0],
            "uid": struct.unpack('<H', h[28:30])[0],
            "mid": struct.unpack('<H', h[30:32])[0],
        }
    except (IndexError, struct.error):
        return {}


def parse_session_setup(data: bytes) -> dict:
    """
    Parseia Session Setup AndX Request (non-extended security, WordCount=13).
    Extrai fingerprint do atacante: NativeOS, NativeLanManager, AccountName, Domain.
    
    Esses campos revelam a ferramenta/SO do atacante:
    - Metasploit Ruby: "Windows 2000 2195" / "Windows 2000 5.0"
    - Impacket Python: "Unix" / "Samba"  
    - Windows real: "Windows 10.0" / "Windows 10.0"
    - CrackMapExec: herda do Impacket
    """
    info = {}
    try:
        smb_start = 4  # após NetBIOS header
        body_start = smb_start + 32  # após SMB header
        
        word_count = data[body_start]
        info["word_count"] = word_count
        
        if word_count == 13:
            # Non-Extended Security Session Setup
            words_start = body_start + 1
            
            info["max_buffer_size"] = struct.unpack('<H', data[words_start+4:words_start+6])[0]
            info["max_mpx_count"] = struct.unpack('<H', data[words_start+6:words_start+8])[0]
            info["vc_number"] = struct.unpack('<H', data[words_start+8:words_start+10])[0]
            info["session_key"] = struct.unpack('<I', data[words_start+10:words_start+14])[0]
            
            oem_pw_len = struct.unpack('<H', data[words_start+14:words_start+16])[0]
            uni_pw_len = struct.unpack('<H', data[words_start+16:words_start+18])[0]
            capabilities = struct.unpack('<I', data[words_start+22:words_start+26])[0]
            
            info["oem_password_len"] = oem_pw_len
            info["unicode_password_len"] = uni_pw_len
            info["capabilities"] = f"0x{capabilities:08x}"
            
            # ByteCount e dados variáveis
            bc_offset = words_start + 26
            byte_count = struct.unpack('<H', data[bc_offset:bc_offset+2])[0]
            info["byte_count"] = byte_count
            
            # Pular passwords
            str_offset = bc_offset + 2 + oem_pw_len + uni_pw_len
            
            # Extrair strings null-terminated (ASCII ou Unicode depende de flags2)
            # Metasploit normalmente envia ASCII aqui
            remaining = data[str_offset:]
            strings = []
            pos = 0
            while pos < len(remaining) and len(strings) < 4:
                # Tentar encontrar null terminator
                null_pos = remaining.find(b'\x00', pos)
                if null_pos == -1:
                    break
                s = remaining[pos:null_pos].decode('ascii', errors='replace')
                if s:  # ignorar strings vazias entre delimitadores
                    strings.append(s)
                pos = null_pos + 1
            
            field_names = ["account_name", "primary_domain", "native_os", "native_lan_manager"]
            for i, name in enumerate(field_names):
                info[name] = strings[i] if i < len(strings) else ""
        
        elif word_count == 12:
            # Extended Security Session Setup (NTLMSSP)
            words_start = body_start + 1
            security_blob_len = struct.unpack('<H', data[words_start+14:words_start+16])[0]
            bc_offset = words_start + 24
            byte_count = struct.unpack('<H', data[bc_offset:bc_offset+2])[0]
            blob_start = bc_offset + 2
            security_blob = data[blob_start:blob_start+security_blob_len]
            
            info["security_blob_len"] = security_blob_len
            info["auth_type"] = "NTLMSSP/SPNEGO"
            
            # Checar se contém NTLMSSP
            if b'NTLMSSP' in security_blob:
                ntlm_offset = security_blob.index(b'NTLMSSP')
                msg_type = struct.unpack('<I', security_blob[ntlm_offset+8:ntlm_offset+12])[0]
                info["ntlmssp_type"] = msg_type
                
                if msg_type == 1:
                    # NEGOTIATE_MESSAGE - flags revelam capabilities do cliente
                    flags = struct.unpack('<I', security_blob[ntlm_offset+12:ntlm_offset+16])[0]
                    info["ntlmssp_flags"] = f"0x{flags:08x}"
                    
                    # Extrair domain e workstation do NTLMSSP Type 1
                    domain_len = struct.unpack('<H', security_blob[ntlm_offset+16:ntlm_offset+18])[0]
                    domain_offset = struct.unpack('<I', security_blob[ntlm_offset+20:ntlm_offset+24])[0]
                    ws_len = struct.unpack('<H', security_blob[ntlm_offset+24:ntlm_offset+26])[0]
                    ws_offset = struct.unpack('<I', security_blob[ntlm_offset+28:ntlm_offset+32])[0]
                    
                    if domain_len > 0 and domain_offset < len(security_blob):
                        info["ntlmssp_domain"] = security_blob[ntlm_offset+domain_offset:ntlm_offset+domain_offset+domain_len].decode('ascii', errors='replace')
                    if ws_len > 0 and ws_offset < len(security_blob):
                        info["ntlmssp_workstation"] = security_blob[ntlm_offset+ws_offset:ntlm_offset+ws_offset+ws_len].decode('ascii', errors='replace')
            
            # Strings após o blob
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
    """Extrai o caminho do compartilhamento do Tree Connect AndX."""
    info = {}
    try:
        body_start = 4 + 32  # NetBIOS + SMB header
        word_count = data[body_start]
        words_start = body_start + 1
        
        # Pular words (word_count * 2) + password_len field
        pw_len = struct.unpack('<H', data[words_start+6:words_start+8])[0]
        bc_offset = words_start + (word_count * 2)
        byte_count = struct.unpack('<H', data[bc_offset:bc_offset+2])[0]
        
        # Password + Path + Service
        path_start = bc_offset + 2 + pw_len
        remaining = data[path_start:]
        
        # Path pode ser Unicode (\\server\share\0\0) ou ASCII
        # Tentar Unicode primeiro (look for double-null)
        double_null = remaining.find(b'\x00\x00')
        if double_null > 0 and double_null < 100:
            path_bytes = remaining[:double_null+1]
            try:
                info["share_path"] = path_bytes.decode('utf-16-le', errors='replace').rstrip('\x00')
            except:
                info["share_path"] = path_bytes.decode('ascii', errors='replace').rstrip('\x00')
        else:
            # ASCII
            null_pos = remaining.find(b'\x00')
            if null_pos > 0:
                info["share_path"] = remaining[:null_pos].decode('ascii', errors='replace')
        
        # Service string após o path
        if 'share_path' in info:
            svc_start = path_start + len(info["share_path"].encode()) + 2  # +null terminators
            svc_remaining = data[svc_start:]
            null_pos = svc_remaining.find(b'\x00')
            if null_pos > 0:
                info["service_type"] = svc_remaining[:null_pos].decode('ascii', errors='replace')
    
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    
    return info


def parse_transaction(data: bytes) -> dict:
    """Extrai informações da Transaction request (named pipe, subcommand)."""
    info = {}
    try:
        body_start = 4 + 32
        word_count = data[body_start]
        words_start = body_start + 1
        
        if word_count >= 14:
            # SMB_COM_TRANSACTION fields
            info["total_param_count"] = struct.unpack('<H', data[words_start+0:words_start+2])[0]
            info["total_data_count"] = struct.unpack('<H', data[words_start+2:words_start+4])[0]
            info["max_param_count"] = struct.unpack('<H', data[words_start+4:words_start+6])[0]
            info["max_data_count"] = struct.unpack('<H', data[words_start+6:words_start+8])[0]
            info["setup_count"] = data[words_start+26]
            
            # Setup words (contêm o subcommand)
            setup_count = data[words_start+26]
            if setup_count >= 1:
                setup_offset = words_start + 28
                subcommand = struct.unpack('<H', data[setup_offset:setup_offset+2])[0]
                info["subcommand"] = f"0x{subcommand:04x}"
                
                # Subcommands conhecidos
                subcmd_names = {
                    0x0023: "PeekNamedPipe",
                    0x0026: "TransactNmPipe", 
                    0x0053: "WaitNamedPipe",
                    0x0001: "SetNamedPipeState",
                }
                info["subcommand_name"] = subcmd_names.get(subcommand, "Unknown")
            
            # Nome do pipe (após ByteCount)
            bc_offset = words_start + (word_count * 2)
            byte_count = struct.unpack('<H', data[bc_offset:bc_offset+2])[0]
            
            # Pipe name starts after padding
            name_start = bc_offset + 2
            remaining = data[name_start:name_start+byte_count]
            null_pos = remaining.find(b'\x00')
            if null_pos > 0:
                info["pipe_name"] = remaining[:null_pos].decode('ascii', errors='replace')
    
    except (IndexError, struct.error) as e:
        info["parse_error"] = str(e)
    
    return info


def build_negotiate_response(dialect_index: int = 3) -> bytes:
    """
    Constrói SMB_COM_NEGOTIATE Response (0x72) simulando Windows 7 SP1 / Server 2008 R2.
    
    Este é o ponto-chave: o Nmap e scanners de vulnerabilidade leem estes campos
    para determinar se o alvo é vulnerável ao MS17-010.
    
    Campos críticos para parecer vulnerável:
    - Dialect: NT LM 0.12 (SMB1)
    - SecurityMode: User-level security, sem message signing required
    - MaxBufferSize, MaxMpxCount: valores típicos do Windows
    - Server GUID: guid aleatório mas fixo
    - Capabilities: indica suporte a NT Status, RPC, Unicode
    """
    smb_header = build_smb1_header(
        command=0x72,  # SMB_COM_NEGOTIATE
        status=0,
        flags=0x98,
        flags2=0xC053   # Unicode | NT Status (SEM Extended Security)
    )

    # Negotiate Response body (non-extended security)
    body = b''
    body += struct.pack("<B", 17)        # Word Count = 17
    body += struct.pack("<H", dialect_index) # Dialect Index (NT LM 0.12)
    body += struct.pack("<B", 0x03)      # Security Mode: User-level, plaintext
    body += struct.pack("<H", 50)        # Max Mpx Count
    body += struct.pack("<H", 1)         # Max Number VCs
    body += struct.pack("<I", 16644)     # Max Buffer Size
    body += struct.pack("<I", 65536)     # Max Raw Size
    body += struct.pack("<I", 0)         # Session Key
    
    # Capabilities SEM Extended Security (0x80000000)
    capabilities = 0x0000F3F7
    body += struct.pack("<I", capabilities)
    
    # System Time (Windows FILETIME)
    now = datetime.datetime.now(datetime.timezone.utc)
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    filetime = int((now - epoch).total_seconds() * 10_000_000)
    body += struct.pack("<Q", filetime)
    
    # Server Time Zone (em minutos, UTC-3 = 180)
    body += struct.pack("<h", 180)
    
    # Encryption Key Length = 8 (challenge de 8 bytes)
    body += struct.pack("<B", 8)
    
    # ByteCount: EncryptionKey(8) + DomainName + ServerName
    encryption_key = b'\x01\x23\x45\x67\x89\xab\xcd\xef'  # 8-byte challenge
    domain_name = 'WORKGROUP\x00'.encode('utf-16-le')
    server_name = 'WIN7-PC\x00'.encode('utf-16-le')
    
    payload = encryption_key + domain_name + server_name
    body += struct.pack("<H", len(payload))  # Byte Count
    body += payload
    
    # Montar pacote completo
    smb_packet = smb_header + body
    packet = netbios_header(len(smb_packet)) + smb_packet
    
    return packet


def build_session_setup_response(uid: int = 100) -> bytes:
    """
    Session Setup response - aceita qualquer autenticação.
    Sem Extended Security, o fluxo é single-round.
    """
    smb_header = build_smb1_header(
        command=0x73,
        status=0,  # STATUS_SUCCESS
        flags=0x98,
        flags2=0xC053,
        uid=uid
    )
    
    body = b''
    body += struct.pack("<B", 3)    # Word Count = 3
    body += struct.pack("<B", 0)    # AndXCommand: No further commands
    body += struct.pack("<B", 0)    # Reserved
    body += struct.pack("<H", 0)    # AndXOffset
    body += struct.pack("<H", 1)    # Action: logged in as GUEST
    # ByteCount: NativeOS + NativeLanManager + PrimaryDomain
    native_os = 'Windows 7 Professional 7601 Service Pack 1\x00'.encode('utf-16-le')
    native_lm = 'Windows 7 Professional 6.1\x00'.encode('utf-16-le')
    primary_domain = 'WORKGROUP\x00'.encode('utf-16-le')
    byte_data = native_os + native_lm + primary_domain
    body += struct.pack("<H", len(byte_data))  # ByteCount
    body += byte_data
    
    smb_packet = smb_header + body
    return netbios_header(len(smb_packet)) + smb_packet


# ============================================================
# CONNECTION HANDLER
# ============================================================

class HoneypointHandler:
    """Gerencia uma conexão individual ao honeypoint."""
    
    def __init__(self, client_socket: socket.socket, client_addr: tuple):
        self.sock = client_socket
        self.ip = client_addr[0]
        self.port = client_addr[1]
        self.interaction_count = 0
        self.raw_data_received = []
        self.authenticated = False
        self.uid = 100
        self.tid = 2048
    
    def handle(self):
        """Loop principal de interação com o cliente."""
        logger.info(f"🎯 Nova conexão: {self.ip}:{self.port}")
        log_event("connection_open", self.ip, self.port, {})
        
        try:
            self.sock.settimeout(30)
            
            while True:
                # Receber dados do cliente
                data = self.sock.recv(4096)
                if not data:
                    break
                
                self.interaction_count += 1
                self.raw_data_received.append(data.hex())
                
                logger.info(
                    f"📨 [{self.ip}:{self.port}] Recebido {len(data)} bytes "
                    f"(interação #{self.interaction_count})"
                )
                log_event("data_received", self.ip, self.port, {
                    "length": len(data),
                    "hex_preview": data[:64].hex(),
                    "interaction": self.interaction_count
                })
                
                # Analisar e responder
                response = self._process_smb(data)
                if response:
                    self.sock.sendall(response)
                    logger.info(
                        f"📤 [{self.ip}:{self.port}] Enviado {len(response)} bytes"
                    )
                    log_event("response_sent", self.ip, self.port, {
                        "length": len(response),
                        "interaction": self.interaction_count
                    })
                else:
                    # Comando não reconhecido - logar e desconectar
                    log_event("unknown_command", self.ip, self.port, {
                        "hex_data": data[:128].hex(),
                        "interaction": self.interaction_count
                    })
                    break
                    
        except socket.timeout:
            logger.info(f"⏰ [{self.ip}:{self.port}] Timeout após {self.interaction_count} interações")
            log_event("timeout", self.ip, self.port, {
                "interactions": self.interaction_count
            })
        except ConnectionResetError:
            logger.info(f"🔌 [{self.ip}:{self.port}] Conexão resetada")
            log_event("connection_reset", self.ip, self.port, {
                "interactions": self.interaction_count
            })
        except Exception as e:
            logger.error(f"❌ [{self.ip}:{self.port}] Erro: {e}")
            log_event("error", self.ip, self.port, {
                "error": str(e),
                "interactions": self.interaction_count
            })
        finally:
            self.sock.close()
            logger.info(
                f"🔒 [{self.ip}:{self.port}] Conexão encerrada "
                f"({self.interaction_count} interações)"
            )
            log_event("connection_close", self.ip, self.port, {
                "total_interactions": self.interaction_count,
                "all_data_hex": self.raw_data_received
            })
    
    def _process_smb(self, data: bytes) -> bytes | None:
        """
        Analisa o pacote recebido e retorna a resposta SMB apropriada.
        
        Fluxo típico de um scanner EternalBlue:
        1. Cliente envia SMB_COM_NEGOTIATE → respondemos com dialeto NT LM 0.12
        2. Cliente envia Session Setup → respondemos com NTLMSSP Challenge
        3. Cliente pode tentar Tree Connect ou o exploit propriamente dito
        """
        # Pular NetBIOS header (4 bytes) para chegar ao SMB
        if len(data) < 8:
            return None
        
        # Verificar se é um pacote SMB válido
        smb_offset = 4  # após NetBIOS header
        
        # SMB1 magic: \xffSMB
        if data[smb_offset:smb_offset+4] == b'\xffSMB':
            command = data[smb_offset + 4]
            return self._handle_smb1(command, data)
        
        # SMB2 magic: \xfeSMB
        elif data[smb_offset:smb_offset+4] == b'\xfeSMB':
            logger.info(f"🔍 [{self.ip}:{self.port}] SMB2 detectado - respondendo com SMB1")
            log_event("smb2_detected", self.ip, self.port, {
                "note": "Cliente tentou SMB2, forçando downgrade para SMB1"
            })
            # Responder com negotiate SMB1 para forçar downgrade
            return build_negotiate_response()
        
        # Pode ser apenas o NetBIOS session request
        elif data[0] == 0x81:
            logger.info(f"🔍 [{self.ip}:{self.port}] NetBIOS Session Request")
            # Responder com Session Positive Response
            return b'\x82\x00\x00\x00'
        
        return None
    
    def _handle_smb1(self, command: int, data: bytes) -> bytes | None:
        """Processa comandos SMB1."""
        
        command_names = {
            0x72: "NEGOTIATE",
            0x73: "SESSION_SETUP",
            0x75: "TREE_CONNECT",
            0x25: "TRANSACTION",
            0x32: "TRANSACTION2",
            0xA0: "NT_TRANSACT",
        }
        
        cmd_name = command_names.get(command, f"UNKNOWN(0x{command:02x})")
        logger.info(f"🔍 [{self.ip}:{self.port}] SMB1 Command: {cmd_name}")
        
        log_event("smb1_command", self.ip, self.port, {
            "command": cmd_name,
            "command_hex": f"0x{command:02x}"
        })
        
        if command == 0x72:  # NEGOTIATE
            idx = parse_dialect_index(data)
            header_info = parse_smb_header(data)
            logger.info(f"🔍 [{self.ip}:{self.port}] Dialect index: {idx}")
            log_event("negotiate_details", self.ip, self.port, {
                "dialect_index": idx,
                "smb_header": header_info
            })
            return build_negotiate_response(idx)
        
        elif command == 0x73:  # SESSION_SETUP
            self.authenticated = True
            session_info = parse_session_setup(data)
            header_info = parse_smb_header(data)
            
            # Fingerprinting do atacante
            native_os = session_info.get("native_os", "")
            native_lm = session_info.get("native_lan_manager", "")
            account = session_info.get("account_name", "")
            domain = session_info.get("primary_domain", "")
            workstation = session_info.get("ntlmssp_workstation", "")
            
            # Identificar ferramenta baseado nas strings
            tool_guess = "Unknown"
            if "2195" in native_os or "Windows 2000" in native_os:
                tool_guess = "Metasploit (Ruby Rex)"
            elif "Unix" in native_os or "Samba" in native_lm:
                tool_guess = "Impacket / CrackMapExec (Python)"
            elif "Windows 10" in native_os:
                tool_guess = "Windows 10 nativo ou PsExec"
            elif "Windows 7" in native_os:
                tool_guess = "Windows 7 nativo"
            
            logger.info(
                f"🕵️ [{self.ip}:{self.port}] FINGERPRINT: "
                f"OS='{native_os}' LM='{native_lm}' "
                f"Account='{account}' Domain='{domain}' "
                f"Tool='{tool_guess}'"
            )
            
            log_event("session_setup_fingerprint", self.ip, self.port, {
                "tool_guess": tool_guess,
                "session_info": session_info,
                "smb_header": header_info
            })
            
            return build_session_setup_response(self.uid)
        
        elif command == 0x75:  # TREE_CONNECT
            tree_info = parse_tree_connect(data)
            share_path = tree_info.get("share_path", "unknown")
            
            logger.info(f"🌲 [{self.ip}:{self.port}] Tree Connect: {share_path}")
            log_event("tree_connect_attempt", self.ip, self.port, {
                "tree_info": tree_info
            })
            return self._build_tree_connect_success()
        
        elif command in (0x25, 0x32, 0xA0):  # TRANSACTION / TRANSACTION2 / NT_TRANSACT
            trans_info = parse_transaction(data)
            pipe_name = trans_info.get("pipe_name", "")
            subcmd = trans_info.get("subcommand_name", "")
            
            log_event("EXPLOIT_ATTEMPT", self.ip, self.port, {
                "alert": "🚨 POSSÍVEL TENTATIVA DE EXPLOIT ETERNALBLUE!",
                "command": cmd_name,
                "transaction_info": trans_info,
                "raw_hex": data.hex(),
                "severity": "HIGH"
            })
            logger.warning(
                f"🚨🚨🚨 [{self.ip}:{self.port}] EXPLOIT ATTEMPT! "
                f"Cmd={cmd_name} Pipe={pipe_name} SubCmd={subcmd}"
            )
            # Simular vulnerabilidade: STATUS_INSUFF_SERVER_RESOURCES
            # Este é exatamente o indicador que o scanner MS17-010 procura
            return self._build_error_response(command, 0xC0000205)
        
        else:
            log_event("unknown_smb_command", self.ip, self.port, {
                "command_hex": f"0x{command:02x}",
                "raw_hex": data[:64].hex()
            })
            return self._build_error_response(command, 0xC0000002)
    
    def _build_tree_connect_success(self) -> bytes:
        """Tree Connect com STATUS_SUCCESS - aceita IPC$."""
        smb_header = build_smb1_header(
            command=0x75, status=0, flags=0x98, flags2=0xC053,
            tid=self.tid, uid=self.uid
        )
        body = b''
        body += struct.pack("<B", 3)    # Word Count = 3
        body += struct.pack("<B", 0)    # AndXCommand
        body += struct.pack("<B", 0)    # Reserved
        body += struct.pack("<H", 0)    # AndXOffset
        body += struct.pack("<H", 1)    # Optional Support (SMB_SUPPORT_SEARCH_BITS)
        # ByteCount: Service + NativeFileSystem
        service = b'IPC\x00'
        native_fs = b'\x00'
        body += struct.pack("<H", len(service) + len(native_fs))
        body += service + native_fs
        smb_packet = smb_header + body
        return netbios_header(len(smb_packet)) + smb_packet

    def _build_error_response(self, command: int, status: int) -> bytes:
        """Constrói uma resposta de erro SMB1."""
        smb_header = build_smb1_header(
            command=command, status=status, tid=self.tid, uid=self.uid
        )
        body = struct.pack("<B", 0) + struct.pack("<H", 0)  # WordCount=0, ByteCount=0
        smb_packet = smb_header + body
        return netbios_header(len(smb_packet)) + smb_packet


# ============================================================
# MAIN SERVER
# ============================================================

class EternalBlueHoneypoint:
    """Servidor principal do Honeypoint."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 445):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.connections = []
    
    def start(self):
        """Inicia o honeypoint."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
        except PermissionError:
            logger.error(
                f"❌ Sem permissão para bind na porta {self.port}. "
                f"Execute como root ou use: sudo python3 {sys.argv[0]}"
            )
            sys.exit(1)
        except OSError as e:
            logger.error(f"❌ Erro no bind: {e}")
            sys.exit(1)
        
        self.server_socket.listen(10)
        self.running = True
        
        logger.info("=" * 60)
        logger.info("🍯 ETERNALBLUE HONEYPOINT ATIVO")
        logger.info(f"🌐 Escutando em {self.host}:{self.port}")
        logger.info(f"📁 Logs: {LOG_DIR}/")
        logger.info(f"📋 Eventos JSON: {LOG_DIR}/events.jsonl")
        logger.info("=" * 60)
        
        log_event("server_start", "0.0.0.0", self.port, {
            "bind_address": self.host,
            "bind_port": self.port
        })
        
        # Signal handlers para shutdown gracioso
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_sock, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                
                handler = HoneypointHandler(client_sock, client_addr)
                thread = threading.Thread(
                    target=handler.handle,
                    daemon=True,
                    name=f"client-{client_addr[0]}:{client_addr[1]}"
                )
                thread.start()
                self.connections.append(thread)
                
            except Exception as e:
                if self.running:
                    logger.error(f"❌ Erro no accept: {e}")
    
    def _shutdown(self, signum, frame):
        """Encerra o servidor graciosamente."""
        logger.info("\n🛑 Encerrando honeypoint...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        log_event("server_stop", "0.0.0.0", self.port, {
            "reason": "signal",
            "signal": signum
        })
        logger.info("✅ Honeypoint encerrado.")
        sys.exit(0)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="EternalBlue Honeypoint - Simulador SMB para Pesquisa",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 honeypoint_eternalblue.py                  # porta 445 (padrão)
  sudo python3 honeypoint_eternalblue.py -p 4455          # porta alternativa
  sudo python3 honeypoint_eternalblue.py -b 192.168.1.50  # bind específico

Testar com nmap:
  nmap -sV -p 445 <IP_DA_VM>
  nmap --script smb-vuln-ms17-010 -p 445 <IP_DA_VM>
        """
    )
    parser.add_argument("-p", "--port", type=int, default=445,
                        help="Porta para escutar (default: 445)")
    parser.add_argument("-b", "--bind", type=str, default="0.0.0.0",
                        help="Endereço para bind (default: 0.0.0.0)")
    
    args = parser.parse_args()
    
    honeypoint = EternalBlueHoneypoint(host=args.bind, port=args.port)
    honeypoint.start()
