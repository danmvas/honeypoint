"""
STAGED — Core
============================
Este pacote é o core genérico do framework. Ele não sabe nada
sobre protocolos específicos (SMB, RDP, etc). Toda lógica de
protocolo fica em drivers/.

Componentes:
  - base.py    : StagedDriver (ABC), DriverMetadata, StageDefinition
  - tracker.py : SCTracker (Stage Coverage tracking + JSON logs)
  - launcher.py: Discovery automático de drivers + execução

Uso por drivers:
  from framework import StagedDriver, DriverMetadata, StageDefinition, SCTracker
"""

from framework.base import StagedDriver, DriverMetadata, StageDefinition
from framework.tracker import SCTracker

__all__ = [
    "StagedDriver",
    "DriverMetadata",
    "StageDefinition",
    "SCTracker",
]