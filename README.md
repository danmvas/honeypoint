# Honeypoint Framework

Ferramenta de pesquisa acadêmica desenvolvida para a dissertação de mestrado da UFPR.
Simula serviços vulneráveis (SMB e RDP) para capturar e medir o comportamento de ferramentas de ataque.

---

## O que é Stage Coverage (SC)?

**Stage Coverage** é a métrica central desta pesquisa. Ela mede quantas etapas do protocolo de ataque uma ferramenta consegue completar contra o honeypoint:

```
SC = etapas completadas / total de etapas
```

- `SC = 0/5 = 0%` → a ferramenta não interagiu com o protocolo
- `SC = 3/5 = 60%` → a ferramenta completou reconhecimento e weaponization
- `SC = 5/5 = 100%` → a ferramenta completou todas as etapas (incluindo tentativa de exploit)

### Por que SC importa para a dissertação?

A maioria das soluções da literatura (Honeyd, HoneyPort, etc.) monitora apenas a conexão TCP, sem emulação do protocolo. Isso dá SC = 1/5 no máximo. O Honeypoint deste trabalho emula o protocolo completo (SMB/RDP) e consegue SC = 5/5, capturando muito mais informação sobre o atacante.

---

## Módulos

| Módulo | CVE | Protocolo | Porta padrão |
|--------|-----|-----------|-------------|
| `eternalblue.py` | CVE-2017-0144 | SMB v1 | 445 |
| `bluekeep.py` | CVE-2019-0708 | RDP | 3389 |

### Etapas do EternalBlue (SMB)

| ID | Nome | Kill Chain | O que captura |
|----|------|-----------|--------------|
| E1 | SMB Negotiate | Reconnaissance | Dialetos suportados, fingerprint do cliente |
| E2 | Session Setup | Reconnaissance | NativeOS, NativeLanManager — revela a ferramenta |
| E3 | Tree Connect IPC$ | Weaponization | Caminho do share acessado |
| E4 | Transaction PeekNamedPipe | Weaponization | Confirmação de verificação de vulnerabilidade |
| E5 | Transaction2 Exploit | Exploitation | Payload malformado capturado |

### Etapas do BlueKeep (RDP)

| ID | Nome | Kill Chain | O que captura |
|----|------|-----------|--------------|
| B1 | X.224 Connection Request | Reconnaissance | Cookie RDP (hostname do atacante), protocolos suportados |
| B2 | Security Negotiation | Reconnaissance | Ausência de NLA confirma alvo vulnerável |
| B3 | MCS Connect Initial | Reconnaissance | Hostname real, resolução de tela, teclado, timezone |
| B4 | Channel Join | Weaponization | Canais virtuais acessados, tentativa de bind MS_T120 |
| B5 | Exploit PDU | Exploitation | Payload Refresh Rect / RDPDR com shellcode |

---

## Como executar

### Requisitos

```bash
python3 --version  # Python 3.10+
sudo apt install nmap metasploit-framework  # ferramentas de teste
```

### Iniciar o framework

```bash
# Todos os módulos (precisa de root para portas < 1024)
sudo python3 main.py

# Apenas EternalBlue
sudo python3 main.py --smb-only

# Apenas BlueKeep
sudo python3 main.py --rdp-only

# Portas alternativas (sem root)
python3 main.py --smb-port 4455 --rdp-port 3390
```

Se uma porta já estiver em uso, o framework mostrará `❌ porta X JÁ EM USO`. Para liberar:

```bash
sudo systemctl stop smbd nmbd   # libera porta 445 (Samba)
sudo systemctl stop xrdp        # libera porta 3389 (xrdp)
```

---

## Como testar corretamente

> **IMPORTANTE:** `nmap -p 445,3389 <IP>` é um scan de porta simples. Ele **não envia dados SMB ou RDP**, apenas verifica se o TCP está aberto. O honeypoint receberá a conexão e falhará imediatamente em B1/E1 porque nenhum dado de protocolo chegou.
>
> Para gerar Stage Coverage, é necessário usar ferramentas que **falam o protocolo**.

### Testar EternalBlue (porta 445)

```bash
# SC = 4/5 — scanner: negocia SMB, autentica, conecta IPC$, verifica vulnerabilidade e PARA
nmap --script smb-vuln-ms17-010 -p 445 127.0.0.1

# SC = 4/5 — mesmo comportamento do nmap: confirma "VULNERABLE" e não explora
msfconsole -x 'use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 127.0.0.1; run'

# SC = 5/5 — exploiter real: envia payload TRANSACTION2 malformado (E5)
msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 127.0.0.1; set PAYLOAD generic/shell_reverse_tcp; set LHOST 127.0.0.1; run'
```

**O que cada ferramenta gera e por quê:**

| Ferramenta | SC | Motivo |
|---|---|---|
| `nmap smb-vuln-ms17-010` | **4/5 = 80%** | Scanner: para após confirmar "VULNERABLE" em E4. Não envia exploit. |
| `metasploit smb_ms17_010` (auxiliary) | **4/5 = 80%** | Também é só um scanner — mesmo comportamento do nmap. |
| `metasploit ms17_010_eternalblue` (exploit) | **5/5 = 100%** | Exploiter: envia os pacotes TRANSACTION2 malformados de E5. |

> **Nota para a dissertação:** a distinção 4/5 vs 5/5 é relevante — permite diferenciar ferramentas de reconhecimento (nmap, scanners) de ferramentas de exploração real (Metasploit exploit). O nmap chegando em 4/5 e identificando o alvo como "VULNERABLE" é o comportamento esperado e correto.

### Testar BlueKeep (porta 3389)

```bash
# Opção 1: nmap com script RDP (envia X.224 CR PDU — aciona B1 e B2)
nmap --script rdp-enum-encryption -p 3389 127.0.0.1

# Opção 2: rdpscan (open-source, aciona B1-B3)
rdpscan 127.0.0.1

# Opção 3: Metasploit scanner BlueKeep (aciona todas as 5 etapas)
msfconsole -x 'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS 127.0.0.1; run'
```

**O que cada ferramenta gera:**
- `nmap --script rdp-enum-encryption` → SC = B1 + B2 (2/5 = 40%)
- `rdpscan` → SC até B3 (3/5 = 60%)
- `Metasploit cve_2019_0708_bluekeep` → SC = 5/5 (completa todas as etapas)

### Por que preciso usar essas ferramentas específicas?

O protocolo RDP funciona assim: **o cliente envia primeiro** (X.224 Connection Request). O honeypoint fica aguardando. Se a ferramenta de teste não enviar esse PDU, o honeypoint nunca recebe dados e falha em B1.

O protocolo SMB também exige que o cliente inicie com `SMB_COM_NEGOTIATE`. Um scan TCP comum não faz isso.

---

## Verificar os logs

```bash
# Logs em tempo real
tail -f ./logs/eternalblue/honeypoint.log
tail -f ./logs/bluekeep/bluekeep_honeypoint.log

# Eventos JSON estruturados
tail -f ./logs/eternalblue/events.jsonl
tail -f ./logs/bluekeep/bluekeep_events.jsonl

# Relatórios SC salvos
ls /var/log/honeypoint/sc_*.json
```

## Gerar relatório comparativo

```bash
# Relatório com comparação contra soluções da literatura
python3 main.py --report

# Tabela LaTeX para a dissertação
python3 main.py --latex
```

---

## Arquitetura

```
main.py          ← Launcher: inicia ambos os módulos em threads
├── eternalblue.py   ← Servidor SMB falso (porta 445)
├── bluekeep.py      ← Servidor RDP falso (porta 3389)
└── sc_tracker.py               ← Métricas de Stage Coverage + comparação com literatura
```

Cada módulo é independente e pode ser executado sozinho:

```bash
sudo python3 eternalblue.py
sudo python3 bluekeep.py
```

---

## Uso exclusivo em homelab / ambiente controlado

Esta ferramenta é para pesquisa acadêmica em ambiente isolado. Não expor para a internet.
