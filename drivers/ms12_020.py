#!/usr/bin/env python3
"""
Driver: MS12-020 (CVE-2012-0002)
==================================
Honeypoint que simula um servidor RDP vulnerável ao MS12-020 (Microsoft
Remote Desktop Use-After-Free DoS), enganando o scanner Metasploit
auxiliary/scanner/rdp/ms12_020_check.

Reusa as stages 1-3 (X.224 CR, Security Negotiation, MCS Connect
Initial) da família RDP-Recon via families.rdp — prova de que o mesmo
"tronco" de reconhecimento RDP do BlueKeep serve para outra CVE real.
O ponto de divergência começa na fase de Attach User / Channel Join:

  M4: Second Attach User Request — Scanner pede um 2º ID de usuário MCS
  M5: Cross-User Channel Bind    — Scanner vincula o 1º usuário a um
                                    canal do 2º usuário; servidor aceita

Diferente do BlueKeep (que faz um único Attach User e testa o canal
MS_T120 31/0), o MS12-020 depende de obter DOIS IDs de usuário
distintos para montar uma vinculação de canal inválida — um mecanismo
de verificação genuinamente diferente, embora compartilhe B1-B3 com o
BlueKeep.

Referência do sinal real: em
modules/auxiliary/scanner/rdp/ms12_020_check.rb (rapid7/metasploit-framework),
o módulo faz duas Attach User Requests, extrai os dois IDs retornados,
e envia um Channel Join Request vinculando o primeiro usuário a um
canal do segundo (`channel_request << [user1, chan2].pack("nn")`). Um
alvo vulnerável aceita o bind e responde normalmente — o módulo
verifica `res[7, 2] == "\\x3e\\x00"` (o byte 0x3e é o próprio tipo de
PDU "channel-join-confirm", já usado por
`families.rdp.build_mcs_channel_join_confirm`). Este driver simula
exatamente essa resposta — aceitar o bind cross-user normalmente, em
vez de rejeitá-lo.

NOTA (mesmo cuidado do MS08-067): o offset exato do sinal do lado do
scanner real precisa ser reconferido durante um teste de handshake
manual antes de considerar o driver definitivo (ver README de
verificação) — a estrutura aqui replica o formato de PDU já validado
para o BlueKeep, mas a posição exata do sinal dentro do envelope
TPKT/X.224 na resposta deve ser conferida contra um teste real.
"""

from typing import Optional

from framework.base import DriverMetadata, StageDefinition
from families import rdp
from drivers._common.logging_utils import setup_driver_logging

LOG_DIR = "./logs/ms12_020"
logger, json_logger, log_event = setup_driver_logging("ms12_020", LOG_DIR)


class MS12020Driver(rdp.RDPFamilyDriver):
    """Driver para simulação de MS12-020 — variante RDP-Recon."""

    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            name="MS12020",
            cve="CVE-2012-0002",
            cve_alias="MS12-020",
            protocol="RDP",
            default_port=3389,
            scanner_module="auxiliary/scanner/rdp/ms12_020_check",
            scanner_tool="Metasploit Framework",
            description="Simula servidor RDP vulnerável ao MS12-020 (cross-user channel bind)",
            family="RDP-Recon",
            stages=rdp.SHARED_RDP_STAGES + [
                StageDefinition(4, "Second Attach User Request",
                    "Scanner solicita um segundo ID de usuário MCS", "RDP"),
                StageDefinition(5, "Cross-User Channel Bind",
                    "Scanner vincula o 1º usuário a um canal do 2º usuário — servidor aceita", "RDP"),
            ]
        )

    def is_default_variant(self) -> bool:
        return False

    def matches_variant(self, event: str, context: dict) -> bool:
        if event != "channel_join":
            return False
        attached = context.get("attached_user_ids", [])
        initiator = context.get("initiator", 0)
        # sinal: pelo menos 2 usuários anexados, e o Channel Join
        # referencia um usuário diferente do último anexado (bind cross-user)
        return len(attached) >= 2 and initiator in attached and initiator != attached[-1]

    def handle_variant_stages(self, handler: "rdp.RDPConnectionHandler",
                               event: str, data: bytes, context: dict) -> Optional[bytes]:
        if event == "channel_join":
            attached = context.get("attached_user_ids", [])
            initiator = context.get("initiator", 0)
            channel_id = context.get("channel_id", 0)

            logger.warning(f"🚨 [{handler.ip}:{handler.port}] Cross-user channel bind: "
                            f"usuário {initiator} (anexados: {attached}) -> canal {channel_id}")

            if 4 not in handler.tracker._completed:
                handler.tracker.complete_stage(4, "Second Attach User Request",
                    source_ip=handler.ip, data={"attached_user_ids": attached})
                log_event("second_attach_user", handler.ip, handler.port,
                           {"attached_user_ids": attached})

            if 5 not in handler.tracker._completed:
                handler.tracker.complete_stage(5, "Cross-User Channel Bind",
                    source_ip=handler.ip, data={
                        "initiator": initiator, "channel_id": channel_id,
                        "attached_user_ids": attached,
                    })
                log_event("VULN_CHECK", handler.ip, handler.port, {
                    "alert": "Scanner verificando vulnerabilidade MS12-020 (cross-user channel bind)",
                    "initiator": initiator, "channel_id": channel_id,
                })

            # Resposta "vulnerável": aceita o bind cross-user normalmente
            # (mesmo builder usado pelo BlueKeep — o sinal do scanner real
            # é justamente ver um Channel Join Confirm normal aqui).
            return rdp.build_mcs_channel_join_confirm(initiator, channel_id)

        return None
