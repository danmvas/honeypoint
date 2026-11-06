#!/usr/bin/env python3
"""
Driver: MS12-020 (CVE-2012-0002)
==================================
Decoy que simula um servidor RDP vulnerável ao MS12-020 (Microsoft
Remote Desktop Use-After-Free DoS), enganando o scanner Metasploit
auxiliary/scanner/rdp/ms12_020_check.

Reusa as stages 1-3 (X.224 CR, Security Negotiation, MCS Connect
Initial) da família RDP-Recon via families.rdp — prova de que o mesmo
"tronco" de reconhecimento RDP do BlueKeep serve para outra CVE real.
O ponto de divergência começa na fase de Attach User / Channel Join:

  M4: Second Attach User Request — Scanner pede um 2º ID de usuário MCS
                                    (é aqui que a conexão é resolvida
                                    para esta variante)
  M5: Channel Join Check         — Channel Join após o 2º Attach User,
                                    aceito pelo servidor (a troca da qual o
                                    scanner tira o veredito)

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
                StageDefinition(5, "Channel Join Check",
                    "Channel Join após o 2º Attach User, aceito pelo servidor (Confirm com "
                    "resultado 0) — a troca da qual o scanner tira o veredito", "RDP"),
            ]
        )

    def is_default_variant(self) -> bool:
        return False

    @staticmethod
    def _is_cross_user_bind(context: dict) -> bool:
        attached = context.get("attached_user_ids", [])
        initiator = context.get("initiator", 0)
        return len(attached) >= 2 and initiator in attached and initiator != attached[-1]

    def matches_variant(self, event: str, context: dict) -> bool:
        attached = context.get("attached_user_ids", [])
        # Sinal: um 2º Attach User Request na mesma conexão. É o
        # comportamento que distingue o check do MS12-020 (o BlueKeep e os
        # clientes normais anexam um único usuário) e acontece ANTES de
        # qualquer Channel Join — resolver só no Channel Join deixava toda
        # conexão que parasse antes disso registrada como BlueKeep.
        if event == "attach_user":
            return len(attached) >= 2
        if event == "channel_join":
            return self._is_cross_user_bind(context)
        return False

    def handle_variant_stages(self, handler: "rdp.RDPConnectionHandler",
                               event: str, data: bytes, context: dict) -> Optional[bytes]:
        attached = context.get("attached_user_ids", [])

        if event in ("attach_user", "channel_join") and len(attached) >= 2 \
                and 4 not in handler.tracker._completed:
            handler.tracker.complete_stage(4, "Second Attach User Request",
                source_ip=handler.ip, data={"attached_user_ids": attached})
            log_event("second_attach_user", handler.ip, handler.port,
                       {"attached_user_ids": attached})

        if event == "channel_join":
            initiator = context.get("initiator", 0)
            channel_id = context.get("channel_id", 0)
            cross_user = self._is_cross_user_bind(context)

            # M5 (Decision 1, opção a): o Channel Join que segue o 2º Attach
            # User é a troca da qual o ms12_020_check tira o veredito (ele lê
            # o Channel Join Confirm com resultado 0). O initiator que o
            # módulo envia vem de bytes do Connect Response e nunca é um
            # usuário anexado — por isso "cross-user" é registrado, não exigido.
            if len(attached) >= 2 and 5 not in handler.tracker._completed:
                handler.tracker.complete_stage(5, "Channel Join Check",
                    source_ip=handler.ip, data={
                        "initiator": initiator, "channel_id": channel_id,
                        "attached_user_ids": attached, "cross_user": cross_user,
                    })
                log_event("VULN_CHECK", handler.ip, handler.port, {
                    "alert": "Scanner verificando vulnerabilidade MS12-020 (Channel Join após 2 Attach User)",
                    "initiator": initiator, "channel_id": channel_id, "cross_user": cross_user,
                })
            logger.warning(f"🚨 [{handler.ip}:{handler.port}] Channel Join após {len(attached)} "
                           f"Attach User: initiator {initiator} -> canal {channel_id} "
                           f"(cross-user: {cross_user})")

            # Resposta "vulnerável": aceita o bind normalmente (o sinal do
            # scanner real é ver um Channel Join Confirm com resultado 0).
            return rdp.build_mcs_channel_join_confirm(initiator, channel_id)

        return None
