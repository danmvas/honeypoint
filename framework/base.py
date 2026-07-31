#!/usr/bin/env python3
"""
Honeypoint Framework — Driver Base Class
==========================================
Define o contrato que qualquer driver de honeypoint deve seguir.

Um driver é responsável por:
  1. Declarar suas stages (etapas do protocolo de reconhecimento)
  2. Implementar o servidor que responde ao scanner
  3. Reportar ao framework quando cada stage é completada

O framework cuida de:
  - Tracking de stages e cálculo de SC
  - Logging estruturado (JSON)
  - Launcher unificado
  - Geração de relatórios
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import datetime


@dataclass
class StageDefinition:
    """Define uma etapa do protocolo de reconhecimento."""
    number: int          # 1-indexed
    name: str            # Ex: "SMB Negotiate"
    description: str     # Ex: "Scanner envia Negotiate Protocol Request"
    protocol_layer: str  # Ex: "SMB", "RDP", "HTTP"


@dataclass
class DriverMetadata:
    """Metadados do driver — o que ele simula."""
    name: str                    # Ex: "EternalBlue"
    cve: str                     # Ex: "CVE-2017-0144"
    cve_alias: str               # Ex: "MS17-010"
    protocol: str                # Ex: "SMB"
    default_port: int            # Ex: 445
    scanner_module: str          # Ex: "auxiliary/scanner/smb/smb_ms17_010"
    scanner_tool: str            # Ex: "Metasploit Framework"
    description: str             # Descrição curta
    stages: list[StageDefinition] = field(default_factory=list)
    family: Optional[str] = None  # Ex: "SMB1-Recon" — agrupa drivers relacionados (família de CVEs)

    @property
    def total_stages(self) -> int:
        return len(self.stages)


class HoneyPointDriver(ABC):
    """
    Classe base abstrata para drivers de honeypoint.
    
    Para criar um novo driver:
    
    1. Herde desta classe
    2. Implemente get_metadata() retornando DriverMetadata com as stages
    3. Implemente start(port, tracker) para iniciar o servidor
    4. Implemente stop() para parar o servidor
    5. No seu servidor, chame tracker.complete_stage(n) quando cada stage for completada
    
    Exemplo mínimo:
    
        class MyDriver(HoneyPointDriver):
            def get_metadata(self) -> DriverMetadata:
                return DriverMetadata(
                    name="MyProtocol",
                    cve="CVE-XXXX-XXXX",
                    ...
                    stages=[
                        StageDefinition(1, "Handshake", "...", "TCP"),
                        StageDefinition(2, "Negotiate", "...", "MyProto"),
                    ]
                )
            
            def start(self, port: int, tracker) -> None:
                # Inicia servidor TCP na porta, usa tracker.complete_stage(n)
                ...
            
            def stop(self) -> None:
                # Para o servidor
                ...
    """

    @abstractmethod
    def get_metadata(self) -> DriverMetadata:
        """Retorna os metadados e stages do driver."""
        ...

    @abstractmethod
    def start(self, port: int, tracker: 'SCTracker') -> None:
        """
        Inicia o servidor do honeypoint.
        
        Args:
            port: Porta TCP para escutar
            tracker: Instância de SCTracker para reportar stages completadas
        """
        ...

    @abstractmethod
    def stop(self) -> None:
        """Para o servidor do honeypoint."""
        ...

    def get_port_override(self) -> Optional[int]:
        """Retorna porta customizada se configurada via CLI, ou None para usar default."""
        return None