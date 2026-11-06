#!/usr/bin/env python3
"""
Setup de logging compartilhado por drivers.

Extrai o boilerplate (logger de texto + logger JSONL de eventos) que
antes existia duplicado quase verbatim em cada driver individual.
"""

import datetime
import json
import logging
import os
from typing import Callable


def setup_driver_logging(short_name: str, log_dir: str,
                          log_filename: str = "staged.log",
                          events_filename: str = "events.jsonl"
                          ) -> tuple[logging.Logger, logging.Logger, Callable]:
    """Cria (ou reaproveita) um logger de texto e um logger JSONL para um driver.

    Retorna (logger, json_logger, log_event) — log_event(event_type, ip, port, details)
    grava uma linha JSON estruturada no events_filename.
    """
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(f"staged.{short_name}")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(f"{log_dir}/{log_filename}")
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(sh)

    json_logger = logging.getLogger(f"staged.{short_name}.json")
    if not json_logger.handlers:
        json_logger.setLevel(logging.INFO)
        jh = logging.FileHandler(f"{log_dir}/{events_filename}")
        jh.setFormatter(logging.Formatter('%(message)s'))
        json_logger.addHandler(jh)

    def log_event(event_type: str, client_ip: str, client_port: int, details: dict) -> None:
        ev = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": event_type, "src_ip": client_ip,
            "src_port": client_port, "details": details,
        }
        json_logger.info(json.dumps(ev, ensure_ascii=False))

    return logger, json_logger, log_event
