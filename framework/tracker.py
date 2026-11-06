#!/usr/bin/env python3
"""
Honeypoint Framework — Stage Coverage (SC) Tracker
====================================================
Rastreia a progressão de um scanner pelas etapas do protocolo
e calcula a métrica Stage Coverage.

SC = completed_stages / total_stages (N)

Este módulo é genérico — não sabe nada sobre SMB, RDP, ou qualquer
protocolo específico. Ele recebe o número total de stages do driver
e registra quando cada uma é completada.
"""

import json
import os
import datetime
import logging
import secrets
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path

LOG_DIR = os.environ.get("HONEYPOINT_LOG_DIR", "/var/log/honeypoint")


@dataclass
class StageEvent:
    """Registro de uma stage completada."""
    stage_number: int
    stage_name: str
    timestamp: str
    source_ip: str = ""
    source_port: int = 0
    data_captured: dict = field(default_factory=dict)


@dataclass
class SessionReport:
    """Relatório completo de uma sessão de scanning."""
    session_id: str
    driver_name: str
    cve: str
    cve_alias: str
    protocol: str
    scanner_tool: str
    scanner_module: str
    total_stages: int
    completed_stages: int = 0
    sc_score: float = 0.0
    start_time: str = ""
    end_time: str = ""
    source_ip: str = ""
    source_port: int = 0
    events: list[StageEvent] = field(default_factory=list)
    deception_success: bool = False
    # Atividade depois da troca que carrega o veredito (ex.: transações após
    # o PeekNamedPipe): registrada, mas fora do SC (Decision 1, opção a).
    activity_beyond_n: list[dict] = field(default_factory=list)


class SCTracker:
    """
    Rastreia o Stage Coverage de uma sessão de scanning.
    
    Uso pelo driver:
    
        tracker = SCTracker(driver_metadata)
        tracker.new_session(source_ip="10.10.10.1")
        
        # Conforme o scanner progride pelas etapas:
        tracker.complete_stage(1, "SMB Negotiate", source_ip="10.10.10.1",
                               data={"dialect": "NT LM 0.12"})
        tracker.complete_stage(2, "Session Setup", source_ip="10.10.10.1")
        ...
        
        # Ao final:
        tracker.finalize_session(deception_success=True)
        sc = tracker.get_sc()  # retorna 5/5 = 1.0
    """

    def __init__(self, driver_name: str, cve: str, cve_alias: str,
                 protocol: str, total_stages: int,
                 scanner_tool: str = "", scanner_module: str = ""):
        self.driver_name = driver_name
        self.cve = cve
        self.cve_alias = cve_alias
        self.protocol = protocol
        self.total_stages = total_stages
        self.scanner_tool = scanner_tool
        self.scanner_module = scanner_module
        
        self._session: Optional[SessionReport] = None
        self._completed: set[int] = set()
        
        self.logger = logging.getLogger(f"honeypoint.{driver_name}")
        
        os.makedirs(LOG_DIR, exist_ok=True)

    @classmethod
    def from_metadata(cls, metadata) -> 'SCTracker':
        """Cria um SCTracker a partir de um DriverMetadata."""
        return cls(
            driver_name=metadata.name,
            cve=metadata.cve,
            cve_alias=metadata.cve_alias,
            protocol=metadata.protocol,
            total_stages=metadata.total_stages,
            scanner_tool=metadata.scanner_tool,
            scanner_module=metadata.scanner_module,
        )

    def fork(self) -> 'SCTracker':
        """Um tracker novo, com os mesmos metadados, para UMA conexão.

        O tracker passado a `start()` é um só por driver; se as conexões o
        compartilhassem, uma conexão nova (`new_session`) zeraria o estado
        de outra ainda aberta. As famílias usam um fork por conexão.
        """
        return SCTracker(self.driver_name, self.cve, self.cve_alias,
                         self.protocol, self.total_stages,
                         self.scanner_tool, self.scanner_module)

    def new_session(self, source_ip: str = "", source_port: int = 0) -> None:
        """Inicia uma nova sessão de tracking."""
        now = datetime.datetime.now(datetime.timezone.utc)
        # Microssegundos + sufixo aleatório: com resolução de 1 s, duas
        # sessões encerradas no mesmo segundo gravavam o mesmo
        # sc_<id>.json e a segunda apagava a primeira.
        session_id = (f"{self.driver_name}_{now.strftime('%Y%m%d_%H%M%S_%f')}"
                      f"_{secrets.token_hex(3)}")

        self._session = SessionReport(
            session_id=session_id,
            driver_name=self.driver_name,
            cve=self.cve,
            cve_alias=self.cve_alias,
            protocol=self.protocol,
            scanner_tool=self.scanner_tool,
            scanner_module=self.scanner_module,
            total_stages=self.total_stages,
            start_time=now.isoformat(),
            source_ip=source_ip,
            source_port=source_port,
        )
        self._completed = set()

        self.logger.info(f"Nova sessão: {session_id} de {source_ip}:{source_port}")

    def complete_stage(self, stage_number: int, stage_name: str = "",
                       source_ip: str = "", source_port: int = 0,
                       data: Optional[dict] = None) -> None:
        """Registra a conclusão de uma stage."""
        if self._session is None:
            self.new_session(source_ip=source_ip)
        
        if stage_number in self._completed:
            return  # já registrada
        
        self._completed.add(stage_number)
        
        event = StageEvent(
            stage_number=stage_number,
            stage_name=stage_name,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source_ip=source_ip or self._session.source_ip,
            source_port=source_port or self._session.source_port,
            data_captured=data or {},
        )
        
        self._session.events.append(event)
        self._session.completed_stages = len(self._completed)
        self._session.sc_score = self.get_sc()
        
        sc_display = f"{len(self._completed)}/{self.total_stages}"
        self.logger.info(
            f"[{self.driver_name}] Stage {stage_number}/{self.total_stages} "
            f"({stage_name}) completada — SC = {sc_display}"
        )

    def note_activity_beyond_n(self, description: str, data: Optional[dict] = None) -> None:
        """Registra atividade além da stage N (não conta para o SC)."""
        if self._session is None:
            return
        self._session.activity_beyond_n.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "description": description,
            "data": data or {},
        })
        self.logger.info(f"[{self.driver_name}] Atividade além da stage N: {description}")

    def get_sc(self) -> float:
        """Retorna o Stage Coverage atual (0.0 a 1.0)."""
        if self.total_stages == 0:
            return 0.0
        return len(self._completed) / self.total_stages

    def get_sc_display(self) -> str:
        """Retorna o SC como string legível (ex: '5/5')."""
        return f"{len(self._completed)}/{self.total_stages}"

    def finalize_session(self, deception_success: bool = False) -> Optional[str]:
        """
        Finaliza a sessão e salva o relatório JSON.
        
        Returns:
            Caminho do arquivo JSON salvo, ou None se não houver sessão.
        """
        if self._session is None:
            return None
        
        self._session.end_time = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        self._session.deception_success = deception_success
        self._session.completed_stages = len(self._completed)
        self._session.sc_score = self.get_sc()
        
        # Salva JSON
        filename = os.path.basename(f"sc_{self._session.session_id}.json")
        _safe_base = os.path.abspath(LOG_DIR)
        _safe_path = os.path.abspath(os.path.join(_safe_base, filename))
        if os.path.commonpath([_safe_base, _safe_path]) != _safe_base:
            raise ValueError("Invalid log path")
        filepath = _safe_path

        report_dict = asdict(self._session)
        
        with open(filepath, "w") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        self.logger.info(
            f"Sessão finalizada: SC = {self.get_sc_display()} "
            f"({'SUCESSO' if deception_success else 'PARCIAL'}) → {filepath}"
        )
        
        return filepath

    def print_status(self) -> None:
        """Imprime o status atual no terminal."""
        sc = self.get_sc_display()
        pct = f"{self.get_sc():.0%}"
        
        print(f"\n{'='*60}")
        print(f"  {self.driver_name} ({self.cve}) — SC = {sc} ({pct})")
        print(f"{'='*60}")
        
        for i in range(1, self.total_stages + 1):
            status = "✅" if i in self._completed else "⬜"
            # Tenta pegar o nome da stage dos eventos
            name = ""
            for ev in (self._session.events if self._session else []):
                if ev.stage_number == i:
                    name = ev.stage_name
                    break
            print(f"  {status} Stage {i}: {name}")
        
        print(f"{'='*60}\n")