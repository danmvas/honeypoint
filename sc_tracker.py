#!/usr/bin/env python3
"""
Stage Coverage (SC) - Framework de Avaliação de Honeypoints
============================================================
Módulo compartilhado que rastreia e avalia a cobertura de etapas
de reconhecimento para cada CVE simulada pelo honeypoint.

Métrica central:
  SC = etapas completadas / total de etapas (N)
  SC = 1.0 → atacante completou 100% do reconhecimento sem detectar engano

Cada CVE define suas etapas e o que constitui "completar" cada uma.
O tracker registra timestamps, dados capturados, e gera relatórios
comparativos com soluções da literatura.
"""

import json
import datetime
import logging
import os
from dataclasses import dataclass, field, asdict
from enum import Enum

LOG_DIR = "/var/log/honeypoint"
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("sc_tracker")


class StageStatus(Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Stage:
    """Uma etapa individual do processo de reconhecimento."""
    id: str                         # ex: "E1", "B3"
    name: str                       # ex: "SMB Negotiate"
    description: str                # ex: "Cliente envia lista de dialetos"
    kill_chain_phase: str           # ex: "Reconnaissance"
    data_captured: dict = field(default_factory=dict)
    status: StageStatus = StageStatus.PENDING
    timestamp_start: str | None = None
    timestamp_end: str | None = None
    
    def complete(self, captured_data: dict | None = None):
        """Marca etapa como completada e registra dados capturados."""
        self.status = StageStatus.COMPLETED
        self.timestamp_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if captured_data:
            self.data_captured.update(captured_data)
    
    def fail(self, reason: str = ""):
        self.status = StageStatus.FAILED
        self.timestamp_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.data_captured["failure_reason"] = reason
    
    def start(self):
        self.timestamp_start = datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class SCTracker:
    """
    Rastreador de Stage Coverage para uma sessão de ataque.
    
    Uso:
        tracker = SCTracker.eternalblue(src_ip, src_port)
        tracker.start_stage("E1")
        tracker.complete_stage("E1", {"dialects": [...], "tool": "Metasploit"})
        ...
        report = tracker.report()
        # report["sc_score"] = 1.0 se todas completaram
    """
    cve_id: str
    cve_name: str
    protocol: str
    port: int
    src_ip: str
    src_port: int
    stages: list[Stage] = field(default_factory=list)
    session_start: str = ""
    session_end: str = ""
    tool_detected: str = ""
    
    def __post_init__(self):
        self.session_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # ── Factory methods para cada CVE ──
    
    @classmethod
    def eternalblue(cls, src_ip: str, src_port: int) -> "SCTracker":
        """Cria tracker com as 5 etapas do EternalBlue (CVE-2017-0144)."""
        tracker = cls(
            cve_id="CVE-2017-0144",
            cve_name="EternalBlue",
            protocol="SMBv1",
            port=445,
            src_ip=src_ip,
            src_port=src_port,
        )
        tracker.stages = [
            Stage(
                id="E1",
                name="SMB Negotiate",
                description="Cliente envia lista de dialetos SMB. "
                            "Fingerprint pela combinação de dialetos.",
                kill_chain_phase="Reconnaissance",
            ),
            Stage(
                id="E2",
                name="Session Setup",
                description="Autenticação com credenciais (geralmente nulas). "
                            "Captura NativeOS, NativeLanManager, Account, Domain.",
                kill_chain_phase="Reconnaissance",
            ),
            Stage(
                id="E3",
                name="Tree Connect IPC$",
                description="Acesso ao share IPC$ via named pipes. "
                            "Confirma intenção maliciosa.",
                kill_chain_phase="Weaponization",
            ),
            Stage(
                id="E4",
                name="Transaction PeekNamedPipe",
                description="Scanner verifica vulnerabilidade via PeekNamedPipe em \\PIPE\\. "
                            "Ponto de decisão do scanner (VULNERABLE vs safe).",
                kill_chain_phase="Weaponization",
            ),
            Stage(
                id="E5",
                name="Transaction2 Exploit",
                description="Envio de pacotes malformados para explorar buffer overflow "
                            "em srv!SrvOS2FeaListSizeToNt. Payload capturado.",
                kill_chain_phase="Exploitation",
            ),
        ]
        return tracker
    
    @classmethod
    def bluekeep(cls, src_ip: str, src_port: int) -> "SCTracker":
        """Cria tracker com as 5 etapas do BlueKeep (CVE-2019-0708)."""
        tracker = cls(
            cve_id="CVE-2019-0708",
            cve_name="BlueKeep",
            protocol="RDP",
            port=3389,
            src_ip=src_ip,
            src_port=src_port,
        )
        tracker.stages = [
            Stage(
                id="B1",
                name="X.224 Connection Request",
                description="Cliente envia CR PDU com cookie RDP. "
                            "Fingerprint pelo cookie e requested protocols.",
                kill_chain_phase="Reconnaissance",
            ),
            Stage(
                id="B2",
                name="Security Negotiation",
                description="Negociação de camada de segurança (TLS/CredSSP/RDP). "
                            "Ausência de NLA indica alvo potencialmente vulnerável.",
                kill_chain_phase="Reconnaissance",
            ),
            Stage(
                id="B3",
                name="MCS Connect Initial",
                description="GCC Conference Create com Client Core Data. "
                            "Captura hostname, resolução, teclado, timezone do atacante.",
                kill_chain_phase="Reconnaissance",
            ),
            Stage(
                id="B4",
                name="Channel Join",
                description="Cliente solicita join em canais virtuais. "
                            "Tentativa de bind MS_T120 em canal != 31 indica exploit.",
                kill_chain_phase="Weaponization",
            ),
            Stage(
                id="B5",
                name="Exploit PDU",
                description="Envio de Refresh Rect PDU ou RDPDR Client Name Request "
                            "com shellcode no kernel pool.",
                kill_chain_phase="Exploitation",
            ),
        ]
        return tracker
    
    # ── Operações de tracking ──
    
    def start_stage(self, stage_id: str):
        """Marca início de uma etapa."""
        stage = self._get_stage(stage_id)
        if stage:
            stage.start()
            logger.info(
                f"📊 SC [{self.src_ip}] [{self.cve_name}] "
                f"Etapa {stage_id} ({stage.name}) INICIADA"
            )
    
    def complete_stage(self, stage_id: str, captured_data: dict | None = None):
        """Marca etapa como completada com dados capturados."""
        stage = self._get_stage(stage_id)
        if stage:
            stage.complete(captured_data)
            completed = self.completed_count
            total = len(self.stages)
            sc = self.sc_score
            logger.info(
                f"✅ SC [{self.src_ip}] [{self.cve_name}] "
                f"Etapa {stage_id} ({stage.name}) COMPLETADA "
                f"[{completed}/{total} = SC {sc:.0%}]"
            )
    
    def fail_stage(self, stage_id: str, reason: str = ""):
        """Marca etapa como falha."""
        stage = self._get_stage(stage_id)
        if stage:
            stage.fail(reason)
            logger.warning(
                f"❌ SC [{self.src_ip}] [{self.cve_name}] "
                f"Etapa {stage_id} ({stage.name}) FALHOU: {reason}"
            )
    
    # ── Métricas ──
    
    @property
    def completed_count(self) -> int:
        return sum(1 for s in self.stages if s.status == StageStatus.COMPLETED)
    
    @property
    def total_stages(self) -> int:
        return len(self.stages)
    
    @property
    def sc_score(self) -> float:
        """Stage Coverage score: 0.0 a 1.0"""
        if not self.stages:
            return 0.0
        return self.completed_count / len(self.stages)
    
    @property
    def max_consecutive_completed(self) -> int:
        """Maior sequência consecutiva de etapas completadas (desde E1/B1)."""
        count = 0
        for stage in self.stages:
            if stage.status == StageStatus.COMPLETED:
                count += 1
            else:
                break
        return count
    
    # ── Relatório ──
    
    def report(self) -> dict:
        """Gera relatório completo da sessão para análise."""
        self.session_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        stages_report = []
        for s in self.stages:
            stages_report.append({
                "id": s.id,
                "name": s.name,
                "kill_chain_phase": s.kill_chain_phase,
                "status": s.status.value,
                "data_captured": s.data_captured,
                "timestamp_start": s.timestamp_start,
                "timestamp_end": s.timestamp_end,
            })
        
        return {
            "cve_id": self.cve_id,
            "cve_name": self.cve_name,
            "protocol": self.protocol,
            "port": self.port,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "tool_detected": self.tool_detected,
            "session_start": self.session_start,
            "session_end": self.session_end,
            "sc_score": round(self.sc_score, 4),
            "sc_display": f"{self.completed_count}/{self.total_stages}",
            "sc_percentage": f"{self.sc_score:.0%}",
            "max_consecutive": self.max_consecutive_completed,
            "stages": stages_report,
        }
    
    def save_report(self, filepath: str | None = None):
        """Salva relatório em JSON."""
        if filepath is None:
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_ip = self.src_ip.replace('.', '_')
            filepath = os.path.join(
                LOG_DIR,
                f"sc_{self.cve_name}_{safe_ip}_{ts}.json"
            )
        
        report = self.report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 SC Report salvo: {filepath}")
        return filepath
    
    def print_summary(self):
        """Imprime resumo visual no console."""
        print()
        print(f"{'='*60}")
        print(f"  STAGE COVERAGE REPORT — {self.cve_name} ({self.cve_id})")
        print(f"{'='*60}")
        print(f"  Atacante: {self.src_ip}:{self.src_port}")
        if self.tool_detected:
            print(f"  Ferramenta: {self.tool_detected}")
        print(f"  Protocolo: {self.protocol} (porta {self.port})")
        print(f"{'─'*60}")
        
        for s in self.stages:
            if s.status == StageStatus.COMPLETED:
                icon = "✅"
            elif s.status == StageStatus.FAILED:
                icon = "❌"
            elif s.status == StageStatus.SKIPPED:
                icon = "⏭️"
            else:
                icon = "⬜"
            
            phase = f"[{s.kill_chain_phase}]"
            print(f"  {icon} {s.id} {s.name:<30} {phase}")
            
            if s.data_captured:
                for key, value in s.data_captured.items():
                    if key == "failure_reason":
                        continue
                    val_str = str(value)[:60]
                    print(f"       └─ {key}: {val_str}")
        
        print(f"{'─'*60}")
        print(f"  SC = {self.completed_count}/{self.total_stages} "
              f"= {self.sc_score:.0%}")
        print(f"  Consecutivas desde início: {self.max_consecutive_completed}")
        print(f"{'='*60}")
        print()
    
    # ── Helpers ──
    
    def _get_stage(self, stage_id: str) -> Stage | None:
        for s in self.stages:
            if s.id == stage_id:
                return s
        logger.warning(f"Stage {stage_id} não encontrada")
        return None


# ============================================================
# COMPARAÇÃO COM SOLUÇÕES DA LITERATURA
# ============================================================

# Stage Coverage estimado das soluções do survey
# ⚠️  Scores são ESTIMATIVAS baseadas na análise dos papers.
#     Precisam ser validados pelo autor da dissertação.
#     Critério: quantas etapas do protocolo (SMB/RDP) a solução
#     conseguiria completar SE fosse configurada para esse serviço.
LITERATURE_SC = {
    "eternalblue": {
        "Proposta (este trabalho)": {
            "sc": "5/5", "score": 1.0,
            "note": "Todas as 5 etapas completadas e verificadas experimentalmente"
        },
        "H4 (Wang 2025)": {
            "sc": "2/5", "score": 0.4,
            "note": "Service Honeypoint usa containers Docker (dionaea); cobre Negotiate+Setup, sem IPC$/vuln check"
        },
        "Liu PHCG (2025)": {
            "sc": "0/5", "score": 0.0,
            "note": "Focado em protocolo PLC (Modbus/S7), sem emulação SMB"
        },
        "Tan (2025)": {
            "sc": "0/5", "score": 0.0,
            "note": "Teoria dos jogos para PLC Honeypoint, sem emulação de protocolo SMB"
        },
        "Ukarande Honeybrid (2025)": {
            "sc": "1/5", "score": 0.2,
            "note": "Framework SDN híbrido, detecta conexão e redireciona, sem protocolo SMB"
        },
        "Rehman (2024)": {
            "sc": "0/5", "score": 0.0,
            "note": "MTD + deception para IoT (MQTT/CoAP), sem emulação SMB"
        },
        "MTDCD (Gao 2021)": {
            "sc": "1/5", "score": 0.2,
            "note": "SDN redireciona tráfego para honeypot; detecta conexão na porta, sem protocolo SMB profundo"
        },
        "Liu (2019)": {
            "sc": "0/5", "score": 0.0,
            "note": "Deception contra APT focado em serviços web, sem emulação SMB"
        },
        "HoneyPort (Filippi 2019)": {
            "sc": "1/5", "score": 0.2,
            "note": "Código aberto monitora porta e loga conexões; sem emulação de protocolo SMB"
        },
        "Arifianto (2018)": {
            "sc": "0/5", "score": 0.0,
            "note": "Honeypot SSH + Port Knocking, sem relação com SMB"
        },
        "Naagas (2018)": {
            "sc": "0/5", "score": 0.0,
            "note": "Defense-through-Deception para DDoS, detecção em camada de rede"
        },
        "Honeyproxy (Papalitsas 2018)": {
            "sc": "0/5", "score": 0.0,
            "note": "Proxy reverso para deception web, sem protocolo SMB"
        },
        "Kyung HoneyProxy (2017)": {
            "sc": "0/5", "score": 0.0,
            "note": "SDN proxy para tráfego suspeito, sem emulação de serviço SMB"
        },
        "Park HoneyPort (2016)": {
            "sc": "1/5", "score": 0.2,
            "note": "Disfarce de servidor via banner; responde na porta mas sem protocolo SMB"
        },
        "Honeyd (Provos 2004)": {
            "sc": "1/5", "score": 0.2,
            "note": "Low-interaction; simula stack TCP/IP e pode responder SYN na 445, sem SMB real"
        },
    },
    "bluekeep": {
        "Proposta (este trabalho)": {
            "sc": "5/5", "score": 1.0,
            "note": "Todas as 5 etapas completadas e verificadas experimentalmente"
        },
        "H4 (Wang 2025)": {
            "sc": "0/5", "score": 0.0,
            "note": "Paper não menciona emulação de RDP entre os 118 serviços"
        },
        "Liu PHCG (2025)": {
            "sc": "0/5", "score": 0.0,
            "note": "Focado em PLC, sem emulação RDP"
        },
        "Tan (2025)": {
            "sc": "0/5", "score": 0.0,
            "note": "Teoria dos jogos para PLC, sem RDP"
        },
        "Ukarande Honeybrid (2025)": {
            "sc": "0/5", "score": 0.0,
            "note": "SDN framework, sem emulação de protocolo RDP"
        },
        "Rehman (2024)": {
            "sc": "0/5", "score": 0.0,
            "note": "IoT deception, sem RDP"
        },
        "MTDCD (Gao 2021)": {
            "sc": "0/5", "score": 0.0,
            "note": "SDN redirect genérico, sem protocolo RDP"
        },
        "Liu (2019)": {
            "sc": "0/5", "score": 0.0,
            "note": "Deception web, sem RDP"
        },
        "HoneyPort (Filippi 2019)": {
            "sc": "0/5", "score": 0.0,
            "note": "Monitora portas, sem emulação RDP"
        },
        "Arifianto (2018)": {
            "sc": "0/5", "score": 0.0,
            "note": "SSH Honeypot, sem RDP"
        },
        "Naagas (2018)": {
            "sc": "0/5", "score": 0.0,
            "note": "DDoS detection, sem RDP"
        },
        "Honeyproxy (Papalitsas 2018)": {
            "sc": "0/5", "score": 0.0,
            "note": "Web proxy deception, sem RDP"
        },
        "Kyung HoneyProxy (2017)": {
            "sc": "0/5", "score": 0.0,
            "note": "SDN proxy, sem RDP"
        },
        "Park HoneyPort (2016)": {
            "sc": "0/5", "score": 0.0,
            "note": "Banner disguise, sem protocolo RDP"
        },
        "Honeyd (Provos 2004)": {
            "sc": "0/5", "score": 0.0,
            "note": "Low-interaction, sem emulação RDP"
        },
    },
}


def compare_with_literature(cve_name: str, our_score: float) -> dict:
    """
    Compara o SC obtido com as soluções da literatura.
    Retorna ranking ordenado por score.
    """
    key = cve_name.lower().replace("-", "").replace(" ", "")
    lit = LITERATURE_SC.get(key, {})
    
    # Atualizar nossa pontuação real
    if "Proposta (este trabalho)" in lit:
        lit["Proposta (este trabalho)"]["score"] = our_score
        n = int(lit["Proposta (este trabalho)"]["sc"].split("/")[1])
        completed = int(our_score * n)
        lit["Proposta (este trabalho)"]["sc"] = f"{completed}/{n}"
    
    # Ordenar por score
    ranking = sorted(lit.items(), key=lambda x: x[1]["score"], reverse=True)
    
    return {
        "cve": cve_name,
        "our_score": our_score,
        "ranking": [
            {"solution": name, **data}
            for name, data in ranking
        ]
    }


def print_comparison(cve_name: str, our_score: float):
    """Imprime tabela comparativa no console."""
    comp = compare_with_literature(cve_name, our_score)
    
    print()
    print(f"{'='*80}")
    print(f"  COMPARAÇÃO SC — {cve_name}")
    print(f"{'='*80}")
    print(f"  {'Solução':<35} {'SC':>6}  {'Score':>6}  Observação")
    print(f"  {'─'*74}")
    
    for entry in comp["ranking"]:
        name = entry["solution"]
        sc = entry["sc"]
        score = entry["score"]
        note = entry.get("note", "")[:50]
        marker = " ◀" if "Proposta" in name else ""
        print(f"  {name:<35} {sc:>6}  {score:>5.0%}  {note}{marker}")
    
    print(f"{'='*80}")
    print()
