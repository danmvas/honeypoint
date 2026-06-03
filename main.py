#!/usr/bin/env python3
"""
Honeypoint Framework — Launcher Unificado
==========================================
Executa os módulos EternalBlue e BlueKeep simultaneamente
e gera relatórios comparativos de Stage Coverage.

Uso:
  sudo python3 main.py                        # Todos os módulos
  sudo python3 main.py --smb-only              # Apenas EternalBlue
  sudo python3 main.py --rdp-only              # Apenas BlueKeep
  sudo python3 main.py --report                # Gera relatório dos dados coletados
  sudo python3 main.py --smb-port 4455 --rdp-port 3390  # Portas alternativas
"""

import argparse
import json
import os
import sys
import glob
import signal
import threading
import datetime
from pathlib import Path

LOG_DIR = "/var/log/honeypoint"
REPORT_DIR = os.path.join(LOG_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ============================================================
# RELATÓRIO COMPARATIVO
# ============================================================

def load_sc_reports(cve_filter: str | None = None) -> list[dict]:
    """Carrega todos os relatórios SC salvos."""
    reports = []
    pattern = os.path.join(LOG_DIR, "sc_*.json")
    
    for filepath in sorted(glob.glob(pattern)):
        try:
            with open(filepath) as f:
                report = json.load(f)
            if cve_filter and report.get("cve_name", "") != cve_filter:
                continue
            report["_filepath"] = filepath
            reports.append(report)
        except (json.JSONDecodeError, IOError) as e:
            print(f"  Aviso: erro ao ler {filepath}: {e}")
    
    return reports


def generate_comparative_report():
    """
    Gera relatório comparativo completo para a dissertação.
    Agrupa por CVE, calcula estatísticas, e compara com a literatura.
    """
    from sc_tracker import LITERATURE_SC
    
    all_reports = load_sc_reports()
    
    if not all_reports:
        print("❌ Nenhum relatório SC encontrado em", LOG_DIR)
        print("   Execute os honeypoints e teste com Metasploit/Nmap primeiro.")
        return
    
    # Agrupar por CVE
    by_cve = {}
    for r in all_reports:
        cve = r.get("cve_name", "Unknown")
        by_cve.setdefault(cve, []).append(r)
    
    # ── Relatório por CVE ──
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_sessions": len(all_reports),
        "cves_tested": list(by_cve.keys()),
        "results": {}
    }
    
    print()
    print("=" * 72)
    print("  RELATÓRIO COMPARATIVO DE STAGE COVERAGE")
    print(f"  Gerado em: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)
    
    for cve_name, sessions in by_cve.items():
        scores = [s.get("sc_score", 0) for s in sessions]
        avg_sc = sum(scores) / len(scores) if scores else 0
        max_sc = max(scores) if scores else 0
        min_sc = min(scores) if scores else 0
        full_coverage = sum(1 for s in scores if s == 1.0)
        
        # Ferramentas detectadas
        tools = {}
        for s in sessions:
            tool = s.get("tool_detected", "Unknown")
            tools[tool] = tools.get(tool, 0) + 1
        
        # Dados capturados por etapa
        stage_completion = {}
        for session in sessions:
            for stage in session.get("stages", []):
                sid = stage["id"]
                stage_completion.setdefault(sid, {"completed": 0, "total": 0, "name": stage["name"]})
                stage_completion[sid]["total"] += 1
                if stage["status"] == "completed":
                    stage_completion[sid]["completed"] += 1
        
        cve_report = {
            "sessions": len(sessions),
            "sc_average": round(avg_sc, 4),
            "sc_max": round(max_sc, 4),
            "sc_min": round(min_sc, 4),
            "full_coverage_sessions": full_coverage,
            "full_coverage_rate": round(full_coverage / len(sessions), 4) if sessions else 0,
            "tools_detected": tools,
            "stage_completion_rates": {
                sid: round(info["completed"] / info["total"], 4) if info["total"] > 0 else 0
                for sid, info in stage_completion.items()
            }
        }
        
        report["results"][cve_name] = cve_report
        
        # ── Print ──
        print()
        print(f"  ┌─ {cve_name} ({sessions[0].get('cve_id', '')}) ─────────")
        print(f"  │ Sessões analisadas: {len(sessions)}")
        print(f"  │ SC médio: {avg_sc:.0%}  (min: {min_sc:.0%}, max: {max_sc:.0%})")
        print(f"  │ Cobertura completa: {full_coverage}/{len(sessions)} sessões")
        print(f"  │")
        print(f"  │ Ferramentas detectadas:")
        for tool, count in sorted(tools.items(), key=lambda x: -x[1]):
            print(f"  │   {tool}: {count} sessões")
        print(f"  │")
        print(f"  │ Taxa de conclusão por etapa:")
        for sid in sorted(stage_completion.keys()):
            info = stage_completion[sid]
            rate = info["completed"] / info["total"] if info["total"] > 0 else 0
            bar = "█" * int(rate * 20) + "░" * (20 - int(rate * 20))
            print(f"  │   {sid} {info['name']:<30} {bar} {rate:.0%}")
        
        # ── Comparação com literatura ──
        lit_key = cve_name.lower().replace("-", "").replace(" ", "")
        if lit_key in LITERATURE_SC:
            print(f"  │")
            print(f"  │ Comparação com a literatura:")
            print(f"  │   {'Solução':<32} {'SC':>6}  {'Score':>6}")
            print(f"  │   {'─'*50}")
            
            entries = list(LITERATURE_SC[lit_key].items())
            # Atualizar nossa pontuação
            for name, data in entries:
                if "Proposta" in name:
                    data["score"] = max_sc
                    n = int(data["sc"].split("/")[1])
                    data["sc"] = f"{int(max_sc * n)}/{n}"
            
            entries.sort(key=lambda x: -x[1]["score"])
            
            for name, data in entries:
                marker = " ◀ " if "Proposta" in name else "   "
                print(f"  │{marker}{name:<32} {data['sc']:>6}  {data['score']:>5.0%}")
            
            # Calcular posição no ranking
            our_rank = 1
            for name, data in entries:
                if "Proposta" not in name and data["score"] > max_sc:
                    our_rank += 1
            
            cve_report["literature_rank"] = our_rank
            cve_report["literature_total"] = len(entries)
        
        print(f"  └{'─'*60}")
    
    # ── Resumo geral ──
    print()
    print(f"  ┌─ RESUMO ─────────────────────────────────────")
    print(f"  │ Total de sessões: {len(all_reports)}")
    print(f"  │ CVEs testadas: {', '.join(by_cve.keys())}")
    
    for cve_name, cve_data in report["results"].items():
        sc = cve_data["sc_max"]
        rank = cve_data.get("literature_rank", "?")
        total = cve_data.get("literature_total", "?")
        print(f"  │ {cve_name}: SC={sc:.0%} (#{rank}/{total} no ranking)")
    
    print(f"  └{'─'*48}")
    print()
    
    # ── Salvar ──
    report_path = os.path.join(REPORT_DIR, f"comparative_{timestamp}.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"  📄 Relatório salvo: {report_path}")
    print()
    
    return report


def generate_latex_table():
    """Gera tabela LaTeX comparativa para inserir na dissertação."""
    from sc_tracker import LITERATURE_SC
    
    all_reports = load_sc_reports()
    
    # Calcular nosso melhor SC por CVE
    best_sc = {}
    for r in all_reports:
        cve = r.get("cve_name", "")
        sc = r.get("sc_score", 0)
        if cve not in best_sc or sc > best_sc[cve]:
            best_sc[cve] = sc
    
    print()
    print("% ── Tabela LaTeX para a dissertação ──")
    print("% Copiar e colar no .tex")
    print()
    print(r"\begin{table}[htbp]")
    print(r"\centering")
    print(r"\caption{Comparação de Stage Coverage entre a solução proposta e trabalhos relacionados}")
    print(r"\label{tab:sc-comparison}")
    print(r"\begin{tabular}{l c c c c}")
    print(r"\hline")
    print(r"\textbf{Solução} & \textbf{EternalBlue} & \textbf{BlueKeep} & \textbf{SC Médio} & \textbf{Ano} \\")
    print(r"\hline")
    
    # Coletar todas as soluções
    all_solutions = set()
    for cve_data in LITERATURE_SC.values():
        all_solutions.update(cve_data.keys())
    
    rows = []
    for solution in sorted(all_solutions):
        eb_data = LITERATURE_SC.get("eternalblue", {}).get(solution, {})
        bk_data = LITERATURE_SC.get("bluekeep", {}).get(solution, {})
        
        eb_sc = eb_data.get("sc", "--")
        bk_sc = bk_data.get("sc", "--")
        
        eb_score = eb_data.get("score", 0)
        bk_score = bk_data.get("score", 0)
        
        # Atualizar proposta com dados reais
        if "Proposta" in solution:
            if "EternalBlue" in best_sc:
                eb_score = best_sc["EternalBlue"]
                eb_sc = f"{int(eb_score * 5)}/5"
            if "BlueKeep" in best_sc:
                bk_score = best_sc["BlueKeep"]
                bk_sc = f"{int(bk_score * 5)}/5"
        
        count = 0
        total = 0
        if eb_data:
            count += eb_score
            total += 1
        if bk_data:
            count += bk_score
            total += 1
        avg = count / total if total > 0 else 0
        
        year = ""
        if "Provos" in solution: year = "2004"
        elif "Filippi" in solution: year = "2019"
        elif "Naagas" in solution: year = "2018"
        elif "Gao" in solution: year = "2021"
        elif "Wang" in solution: year = "2025"
        elif "Rehman" in solution: year = "2024"
        elif "Proposta" in solution: year = "2026"
        
        bold = r"\textbf" if "Proposta" in solution else ""
        
        if bold:
            rows.append(
                (avg, f"\\textbf{{{solution}}} & \\textbf{{{eb_sc}}} & "
                       f"\\textbf{{{bk_sc}}} & \\textbf{{{avg:.0%}}} & "
                       f"\\textbf{{{year}}} \\\\")
            )
        else:
            rows.append(
                (avg, f"{solution} & {eb_sc} & {bk_sc} & {avg:.0%} & {year} \\\\")
            )
    
    # Ordenar por avg score descending
    rows.sort(key=lambda x: -x[0])
    for _, row in rows:
        print(row)
    
    print(r"\hline")
    print(r"\end{tabular}")
    print(r"\end{table}")
    print()


# ============================================================
# LAUNCHER
# ============================================================

def _port_available(port: int) -> bool:
    """Verifica se a porta está disponível para bind."""
    import socket as _sock
    s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_modules(smb_port: int = 445, rdp_port: int = 3389,
                smb_only: bool = False, rdp_only: bool = False):
    """Executa os módulos de honeypoint em threads separadas."""

    print()
    print("=" * 60)
    print("  🍯 HONEYPOINT FRAMEWORK")
    print("  Dissertação de Mestrado — UFPR")
    print("=" * 60)

    threads = []
    any_failed = False

    if not rdp_only:
        if not _port_available(smb_port):
            print(f"  ❌ EternalBlue (SMB) — porta {smb_port} JÁ EM USO")
            print(f"     Execute: sudo ss -tlnp | grep :{smb_port}")
            any_failed = True
        else:
            from eternalblue import EternalBlueHoneypoint
            smb_hp = EternalBlueHoneypoint(port=smb_port)
            t_smb = threading.Thread(
                target=smb_hp.start, daemon=True, name="eternalblue"
            )
            t_smb.start()
            threads.append(("EternalBlue (SMB)", t_smb, smb_port))
            print(f"  ✅ EternalBlue (SMB) — porta {smb_port}")

    if not smb_only:
        if not _port_available(rdp_port):
            print(f"  ❌ BlueKeep (RDP) — porta {rdp_port} JÁ EM USO")
            print(f"     Execute: sudo ss -tlnp | grep :{rdp_port}")
            any_failed = True
        else:
            from bluekeep import BlueKeepHoneypoint
            rdp_hp = BlueKeepHoneypoint(port=rdp_port)
            t_rdp = threading.Thread(
                target=rdp_hp.start, daemon=True, name="bluekeep"
            )
            t_rdp.start()
            threads.append(("BlueKeep (RDP)", t_rdp, rdp_port))
            print(f"  ✅ BlueKeep (RDP) — porta {rdp_port}")

    if any_failed and not threads:
        print("=" * 60)
        sys.exit(1)

    print()
    print(f"  📁 Logs: {LOG_DIR}/")
    print(f"  📊 SC Reports: {LOG_DIR}/sc_*.json")
    print(f"  📋 Relatório: python3 {sys.argv[0]} --report")
    print()
    print("  Testar com:")
    print(f"    nmap --script smb-vuln-ms17-010 -p {smb_port} 127.0.0.1")
    print(f"    nmap --script rdp-enum-encryption -p {rdp_port} 127.0.0.1")
    print("=" * 60)
    print()

    def shutdown(sig, frame):
        print("\n🛑 Encerrando framework...")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        for _, thread, _ in threads:
            thread.join()
    except KeyboardInterrupt:
        sys.exit(0)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Honeypoint Framework — Launcher e Relatórios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modos de operação:

  Execução:
    sudo python3 main.py                          # Todos os módulos
    sudo python3 main.py --smb-only --smb-port 4455
    sudo python3 main.py --rdp-only --rdp-port 3390

  Relatórios:
    python3 main.py --report                      # Relatório comparativo
    python3 main.py --latex                        # Tabela LaTeX

  Testar:
    # EternalBlue:
    msfconsole -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS <IP>; set RPORT 4455; run'
    
    # BlueKeep:
    msfconsole -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS <IP>; set RPORT 3390; run'
        """
    )
    
    parser.add_argument("--smb-port", type=int, default=445,
                        help="Porta SMB/EternalBlue (default: 445)")
    parser.add_argument("--rdp-port", type=int, default=3389,
                        help="Porta RDP/BlueKeep (default: 3389)")
    parser.add_argument("--smb-only", action="store_true",
                        help="Executar apenas EternalBlue")
    parser.add_argument("--rdp-only", action="store_true",
                        help="Executar apenas BlueKeep")
    parser.add_argument("--report", action="store_true",
                        help="Gerar relatório comparativo")
    parser.add_argument("--latex", action="store_true",
                        help="Gerar tabela LaTeX para dissertação")
    
    args = parser.parse_args()
    
    if args.report:
        generate_comparative_report()
    elif args.latex:
        generate_latex_table()
    else:
        run_modules(
            smb_port=args.smb_port,
            rdp_port=args.rdp_port,
            smb_only=args.smb_only,
            rdp_only=args.rdp_only,
        )