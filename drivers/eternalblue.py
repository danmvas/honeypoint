#!/usr/bin/env python3
"""
Driver: EternalBlue (CVE-2017-0144 / MS17-010)
===============================================
Honeypoint que simula um servidor SMB vulnerável ao EternalBlue,
enganando o scanner Metasploit auxiliary/scanner/smb/smb_ms17_010.

Reusa as stages 1-3 (Negotiate, Session Setup, Tree Connect IPC$) da
família SMB1-Recon via families.smb — é a variante
"default" da família: qualquer conexão SMB na porta 445 que não seja
reconhecida por outra variante registrada (ex: MS08-067) cai aqui,
preservando o comportamento genérico que já existia antes da família
ser extraída.

Stages 4-5 (ponto de divergência real do EternalBlue):
  E4: PeekNamedPipe         — Scanner envia Trans PeekNamedPipe
  E5: Vuln Check Response   — Scanner recebe STATUS_INSUFF_SERVER_RESOURCES

O sinal comportamental distinguidor é a sequência E3→E4:
IPC$ access seguido de PeekNamedPipe SEM acessar recursos reais.
"""

from typing import Optional

from framework.base import DriverMetadata, StageDefinition
from families import smb
from drivers._common.logging_utils import setup_driver_logging

LOG_DIR = "./logs/eternalblue"
logger, json_logger, log_event = setup_driver_logging("eternalblue", LOG_DIR)


class EternalBlueDriver(smb.SMBFamilyDriver):
    """Driver para simulação de EternalBlue/MS17-010 — variante default da família SMB1-Recon."""

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
            family="SMB1-Recon",
            stages=smb.SHARED_SMB_STAGES + [
                StageDefinition(4, "PeekNamedPipe",
                    "Scanner envia Trans PeekNamedPipe para testar named pipes", "SMB"),
                StageDefinition(5, "Vuln Check",
                    "Scanner recebe STATUS_INSUFF_SERVER_RESOURCES indicando vulnerabilidade", "SMB"),
            ]
        )

    def is_default_variant(self) -> bool:
        return True

    def matches_variant(self, command: int, parsed: dict) -> bool:
        return command in (0x25, 0x32, 0xA0)

    def handle_variant_stages(self, handler: "smb.SMBConnectionHandler",
                               command: int, data: bytes, parsed: dict) -> Optional[bytes]:
        command_names = {0x25: "TRANSACTION", 0x32: "TRANSACTION2", 0xA0: "NT_TRANSACT"}
        cmd_name = command_names.get(command, f"UNKNOWN(0x{command:02x})")
        logger.info(f"🔍 [{handler.ip}:{handler.port}] SMB1 Command: {cmd_name}")

        trans_info = parsed if parsed else smb.parse_transaction(data)
        pipe_name = trans_info.get("pipe_name", "")
        subcmd = trans_info.get("subcommand_name", "")
        e4_done = 4 in handler.tracker._completed

        if not e4_done and command == 0x25:
            # E4: PeekNamedPipe (vuln check)
            handler.tracker.complete_stage(4, "PeekNamedPipe",
                source_ip=handler.ip, data={"pipe_name": pipe_name, "subcommand": subcmd})
            log_event("VULN_CHECK", handler.ip, handler.port, {
                "alert": "Scanner verificando vulnerabilidade MS17-010",
                "pipe_name": pipe_name, "subcommand": subcmd
            })
            logger.warning(f"🔍 [{handler.ip}:{handler.port}] VULN CHECK: Pipe={pipe_name} SubCmd={subcmd}")
        else:
            # E5: exploit attempt
            handler.tracker.complete_stage(5, "Vuln Check Response",
                source_ip=handler.ip, data={
                    "command": cmd_name, "pipe_name": pipe_name,
                    "payload_size": len(data), "payload_hex_preview": data[:128].hex()
                })
            log_event("EXPLOIT_ATTEMPT", handler.ip, handler.port, {
                "alert": "TENTATIVA DE EXPLOIT ETERNALBLUE",
                "command": cmd_name, "raw_hex": data.hex()
            })
            logger.warning(f"🚨 [{handler.ip}:{handler.port}] EXPLOIT ATTEMPT! Cmd={cmd_name}")

        return handler.build_error_response(command, 0xC0000205)
