"""
Families — tronco de protocolo compartilhado por famílias de CVEs.

Terceira camada da arquitetura, entre framework/ (core genérico, sem
protocolo) e drivers/ (CVE específica):

  framework/  → core genérico (tracking de stages, logging, launcher)
  families/   → tronco compartilhado por protocolo (SMB1-Recon, RDP-Recon, ...)
  drivers/    → CVE específica (arquivo fino, só a divergência real)

Cada módulo aqui (smb.py, rdp.py, ...) define uma base de família
(ex: SMBFamilyDriver) com os estágios iniciais idênticos entre CVEs do
mesmo protocolo, um listener de porta compartilhado entre variantes, e
o dispatch dinâmico que resolve qual CVE trata o resto da conexão.

Não é descoberto pelo launcher — framework/launcher.py.discover_drivers()
só varre drivers/*.py (não recursivo).
"""
