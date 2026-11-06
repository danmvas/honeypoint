#!/usr/bin/env python3
"""
STAGED — Launcher
=================================
Descobre drivers instalados, carrega e executa simultaneamente.

Uso:
  sudo python3 -m framework.launcher                          # Todos os drivers
  sudo python3 -m framework.launcher --driver eternalblue     # Driver específico
  sudo python3 -m framework.launcher --list                   # Lista drivers disponíveis
  sudo python3 -m framework.launcher --report                 # Relatório dos dados coletados
  
Instalando drivers:
  Coloque seu driver em drivers/ e ele será descoberto automaticamente.
  O driver deve herdar de framework.base.StagedDriver.
"""

import argparse
import importlib
import inspect
import json
import glob
import os
import signal
import sys
import threading
import logging
from pathlib import Path

from framework.base import StagedDriver
from framework.tracker import SCTracker, LOG_DIR

# Diretório onde os drivers ficam
DRIVERS_DIR = Path(__file__).parent.parent / "drivers"


def setup_logging(verbose: bool = False) -> None:
    """Configura logging do framework."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%H:%M:%S")


def discover_drivers() -> dict[str, type[StagedDriver]]:
    """
    Descobre todos os drivers disponíveis no diretório drivers/.
    
    Percorre todos os arquivos .py em drivers/, importa, e coleta
    classes que herdam de StagedDriver.
    
    Returns:
        Dict de {nome_lowercase: classe_do_driver}
    """
    drivers = {}
    
    if not DRIVERS_DIR.exists():
        logging.warning(f"Diretório de drivers não encontrado: {DRIVERS_DIR}")
        return drivers
    
    # Adiciona o diretório pai ao path para imports funcionarem
    parent = str(DRIVERS_DIR.parent)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    
    for py_file in DRIVERS_DIR.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        
        module_name = f"drivers.{py_file.stem}"
        try:
            module = importlib.import_module(module_name)
        except Exception as e:
            logging.warning(f"Erro ao importar {module_name}: {e}")
            continue
        
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, StagedDriver) 
                and obj is not StagedDriver):
                meta = obj().get_metadata()
                key = meta.name.lower().replace(" ", "_")
                drivers[key] = obj
                logging.debug(f"Driver descoberto: {key} ({meta.cve})")
    
    return drivers


def list_drivers(drivers: dict) -> None:
    """Lista os drivers disponíveis."""
    print(f"\n{'='*70}")
    print(f"  STAGED — Drivers Disponíveis")
    print(f"{'='*70}")
    
    if not drivers:
        print("  Nenhum driver encontrado em drivers/")
        print(f"  Crie um driver herdando de framework.base.StagedDriver")
    else:
        metas = {key: cls().get_metadata() for key, cls in drivers.items()}
        has_family = any(m.family for m in metas.values())
        if has_family:
            print(f"  {'Nome':<20} {'CVE':<18} {'Protocolo':<10} {'Porta':<8} {'Stages':<8} {'Família'}")
            print(f"  {'─'*80}")
            for key in sorted(metas):
                meta = metas[key]
                print(f"  {meta.name:<20} {meta.cve:<18} {meta.protocol:<10} "
                      f"{meta.default_port:<8} {meta.total_stages:<8} {meta.family or '-'}")
        else:
            print(f"  {'Nome':<20} {'CVE':<18} {'Protocolo':<10} {'Porta':<8} {'Stages'}")
            print(f"  {'─'*66}")
            for key in sorted(metas):
                meta = metas[key]
                print(f"  {meta.name:<20} {meta.cve:<18} {meta.protocol:<10} "
                      f"{meta.default_port:<8} {meta.total_stages}")
    
    print(f"{'='*70}\n")


def run_driver(driver_cls: type[StagedDriver], 
               port_override: int | None = None) -> None:
    """Instancia e executa um driver."""
    driver = driver_cls()
    meta = driver.get_metadata()
    port = port_override or meta.default_port
    
    tracker = SCTracker.from_metadata(meta)
    
    logging.info(f"Iniciando {meta.name} ({meta.cve}) na porta {port}")
    logging.info(f"  Scanner esperado: {meta.scanner_module}")
    logging.info(f"  Total de stages: {meta.total_stages}")
    
    driver.start(port, tracker)


def generate_report() -> None:
    """Gera relatório de todas as sessões registradas."""
    pattern = os.path.join(LOG_DIR, "sc_*.json")
    reports = []
    
    for filepath in sorted(glob.glob(pattern)):
        try:
            with open(filepath) as f:
                reports.append(json.load(f))
        except (json.JSONDecodeError, IOError) as e:
            print(f"  Aviso: {filepath}: {e}")
    
    if not reports:
        print(f"Nenhum relatório encontrado em {LOG_DIR}")
        return
    
    # Agrupa por driver
    by_driver: dict[str, list] = {}
    for r in reports:
        name = r.get("driver_name", "unknown")
        by_driver.setdefault(name, []).append(r)
    
    print(f"\n{'='*70}")
    print(f"  STAGED — Relatório de Sessões")
    print(f"{'='*70}")
    
    for driver_name, sessions in sorted(by_driver.items()):
        cve = sessions[0].get("cve", "")
        total = sessions[0].get("total_stages", 0)
        
        print(f"\n  Driver: {driver_name} ({cve})")
        print(f"  {'─'*50}")
        
        for s in sessions:
            completed = s.get("completed_stages", 0)
            sc = f"{completed}/{total}"
            success = "✅" if s.get("deception_success") else "❌"
            src = s.get("source_ip", "?")
            ts = s.get("start_time", "?")[:19]
            print(f"    {ts}  SC={sc}  {success}  src={src}")
        
        # Estatísticas
        scores = [s.get("sc_score", 0) for s in sessions]
        avg = sum(scores) / len(scores)
        max_sc = max(scores)
        successes = sum(1 for s in sessions if s.get("deception_success"))
        
        print(f"  {'─'*50}")
        print(f"  Sessões: {len(sessions)}  |  "
              f"SC médio: {avg:.0%}  |  "
              f"SC máximo: {max_sc:.0%}  |  "
              f"Sucessos: {successes}/{len(sessions)}")
    
    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="STAGED — Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  sudo python3 -m framework.launcher                          # Todos os drivers
  sudo python3 -m framework.launcher --driver eternalblue     # Apenas um
  sudo python3 -m framework.launcher --list                   # Lista drivers
  sudo python3 -m framework.launcher --report                 # Relatório

Como testar:
  # EternalBlue:
  msfconsole -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS <IP>; run'
  
  # BlueKeep:
  msfconsole -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS <IP>; run'
        """
    )
    
    parser.add_argument("--driver", type=str, default=None,
                        help="Nome do driver específico para executar")
    parser.add_argument("--port", type=int, default=None,
                        help="Porta override (para driver único)")
    parser.add_argument("--list", action="store_true",
                        help="Lista drivers disponíveis")
    parser.add_argument("--report", action="store_true",
                        help="Gera relatório das sessões")
    parser.add_argument("--verbose", action="store_true",
                        help="Logging detalhado")
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    if args.report:
        generate_report()
        return
    
    drivers = discover_drivers()
    
    if args.list:
        list_drivers(drivers)
        return
    
    if not drivers:
        print("Nenhum driver encontrado. Coloque drivers em drivers/")
        sys.exit(1)
    
    # Seleciona drivers para executar
    if args.driver:
        key = args.driver.lower()
        if key not in drivers:
            print(f"Driver '{key}' não encontrado. Disponíveis: {list(drivers.keys())}")
            sys.exit(1)
        to_run = {key: drivers[key]}
    else:
        to_run = drivers
    
    # Executa em threads
    threads = []
    stop_event = threading.Event()
    
    def signal_handler(sig, frame):
        print("\n\nParando todos os drivers...")
        stop_event.set()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"\n  STAGED — Iniciando {len(to_run)} driver(s)\n")
    
    for key, cls in to_run.items():
        port = args.port if (args.driver and args.port) else None
        t = threading.Thread(
            target=run_driver,
            args=(cls, port),
            daemon=True,
            name=f"driver-{key}"
        )
        t.start()
        threads.append(t)
    
    # Aguarda até Ctrl+C
    stop_event.wait()


if __name__ == "__main__":
    main()