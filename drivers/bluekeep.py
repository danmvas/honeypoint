#!/usr/bin/env python3
"""
Driver: BlueKeep (CVE-2019-0708)
=================================
Honeypoint que simula um servidor RDP vulnerável ao BlueKeep,
enganando o scanner Metasploit auxiliary/scanner/rdp/cve_2019_0708_bluekeep.

Reusa as stages 1-3 (X.224 CR, Security Negotiation, MCS Connect
Initial) da família RDP-Recon via families.rdp — é a variante
"default" da família: qualquer Channel Join que não seja reconhecido
por outra variante registrada (ex: MS12-020) cai aqui, preservando o
comportamento genérico que já existia antes da família ser extraída.

Stages 4-5 (ponto de divergência real do BlueKeep):
  B4: Channel Join   — Scanner solicita join nos canais virtuais (MS_T120 = canal 31/0)
  B5: Exploit PDU    — Scanner envia payload de exploit (MCS Send Data)
"""

from typing import Optional

from framework.base import DriverMetadata, StageDefinition
from families import rdp
from drivers._common.logging_utils import setup_driver_logging

LOG_DIR = "./logs/bluekeep"
logger, json_logger, log_ev = setup_driver_logging(
    "bluekeep", LOG_DIR,
    log_filename="bluekeep_honeypoint.log",
    events_filename="bluekeep_events.jsonl")


class BlueKeepDriver(rdp.RDPFamilyDriver):
    """Driver para simulação de BlueKeep/CVE-2019-0708 — variante default da família RDP-Recon."""

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
            family="RDP-Recon",
            stages=rdp.SHARED_RDP_STAGES + [
                StageDefinition(4, "Channel Join",
                    "Scanner solicita join nos canais virtuais", "RDP"),
                StageDefinition(5, "Exploit PDU",
                    "Scanner envia payload de exploit", "RDP"),
            ]
        )

    def is_default_variant(self) -> bool:
        return True

    def matches_variant(self, event: str, context: dict) -> bool:
        # Fluxo normal: um único usuário anexado, sem bind cross-user.
        # Nunca é de fato consultado pelo resolver (variantes default são
        # puladas na busca), mas documenta o sinal "normal" da família.
        return event == "channel_join" and len(context.get("attached_user_ids", [])) <= 1

    def handle_variant_stages(self, handler: "rdp.RDPConnectionHandler",
                               event: str, data: bytes, context: dict) -> Optional[bytes]:
        if event == "channel_join":
            channel_id = context.get("channel_id", 0)
            initiator = context.get("initiator", 0)
            ms_t120_attempted = channel_id in (31, 0)
            if ms_t120_attempted:
                logger.warning(f"🚨 [{handler.ip}:{handler.port}] MS_T120 channel bind! (canal {channel_id})")
            logger.info(f"📡 [{handler.ip}:{handler.port}] MCS Channel Join: {channel_id}")
            if 4 not in handler.tracker._completed:
                handler.tracker.complete_stage(4, "Channel Join",
                    source_ip=handler.ip, data={
                        "channels_joined": handler.channels_joined,
                        "ms_t120_attempted": ms_t120_attempted,
                    })
            return rdp.build_mcs_channel_join_confirm(initiator, channel_id)

        elif event == "send_data":
            log_ev("rdp_possible_exploit", handler.ip, handler.port, {
                "alert": "POSSÍVEL EXPLOIT BLUEKEEP",
                "pdu_size": len(data), "channels": handler.channels_joined,
            })
            logger.warning(f"🚨 [{handler.ip}:{handler.port}] POSSÍVEL EXPLOIT! {len(data)} bytes")
            handler.tracker.complete_stage(5, "Exploit PDU",
                source_ip=handler.ip, data={
                    "payload_size": len(data),
                    "payload_hex_preview": data[:128].hex()
                })
            return None

        return None
