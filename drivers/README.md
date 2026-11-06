# STAGED Drivers

## Como criar um novo driver

Um driver é um módulo Python que implementa a simulação de um protocolo específico para enganar um scanner de reconhecimento.

### 1. Crie o arquivo em `drivers/`

```python
# drivers/meu_protocolo.py
from framework import StagedDriver, DriverMetadata, StageDefinition, SCTracker

class MeuProtocoloDriver(StagedDriver):
    
    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            name="MeuProtocolo",
            cve="CVE-XXXX-XXXX",
            cve_alias="NomePopular",
            protocol="PROTO",
            default_port=9999,
            scanner_module="auxiliary/scanner/proto/cve_xxxx",
            scanner_tool="Metasploit Framework",
            description="Simula servidor PROTO vulnerável",
            stages=[
                StageDefinition(1, "Handshake", "Descrição...", "PROTO"),
                StageDefinition(2, "Negotiate", "Descrição...", "PROTO"),
                StageDefinition(3, "VulnCheck", "Descrição...", "PROTO"),
            ]
        )
    
    def start(self, port: int, tracker: SCTracker) -> None:
        # Inicia servidor TCP, usa tracker.complete_stage(n, ...)
        ...
    
    def stop(self) -> None:
        # Para o servidor
        ...
```

### 2. Pronto — o launcher descobre automaticamente

```bash
python3 -m framework.launcher --list          # Verifica se aparece
sudo python3 -m framework.launcher --driver meuprotocolo
```

### 3. Como definir as stages

Analise o módulo `auxiliary/scanner/` do Metasploit para o CVE alvo. Decomponha o fluxo de reconhecimento em etapas sequenciais do protocolo. Cada troca de mensagem onde o scanner espera uma resposta específica é uma stage.

### Drivers incluídos

| Driver       | CVE            | Protocolo | Stages | Scanner Metasploit                              |
|-------------|----------------|-----------|--------|--------------------------------------------------|
| EternalBlue | CVE-2017-0144 | SMB       | 5      | auxiliary/scanner/smb/smb_ms17_010              |
| BlueKeep    | CVE-2019-0708 | RDP       | 5      | auxiliary/scanner/rdp/cve_2019_0708_bluekeep    |
| MS12-020    | CVE-2012-0002 | RDP       | 5      | auxiliary/scanner/rdp/ms12_020_check            |

> Todo driver precisa mapear para um scanner de **reconhecimento** real e seguro (categoria
> `auxiliary/scanner/` do Metasploit, ou equivalente) — nunca a um módulo `exploit/`, mesmo em modo
> `check`, nem a um script marcado `intrusive`/`dos`. Uma CVE sem scanner dedicado seguro não deve
> virar driver (ex: MS08-067 foi avaliado e descartado por esse motivo — ver `README.md` raiz).

## Drivers de família (várias CVEs, mesmo tronco de protocolo)

Quando duas ou mais CVEs compartilham os primeiros passos de reconhecimento
de um protocolo (ex: qualquer scanner SMBv1 começa com Negotiate → Session
Setup → Tree Connect IPC$), não crie um driver isolado do zero — herde de
uma base de família em `families/` (diretório de topo, irmão de `framework/`
e `drivers/` — ver `families/README.md` para o mecanismo completo). Hoje
existem `families/smb.py` (`SMBFamilyDriver`, usada por `eternalblue.py`) e
`families/rdp.py` (`RDPFamilyDriver`, usada por `bluekeep.py` e
`ms12_020.py`).

Para adicionar uma nova CVE à família SMB1-Recon:

```python
from families import smb  # importe o módulo, não a classe
# (import direto da classe quebra a descoberta automática de drivers —
#  discover_drivers() inspeciona todo nome de classe visível no módulo)

class MinhaNovaCveDriver(smb.SMBFamilyDriver):
    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            ..., family="SMB1-Recon",
            stages=smb.SHARED_SMB_STAGES + [
                StageDefinition(4, "...", "...", "SMB"),
            ],
        )

    def is_default_variant(self) -> bool:
        return False  # True só para o driver "catch-all" da família (hoje: EternalBlue)

    def matches_variant(self, command: int, parsed: dict) -> bool:
        # sinal que identifica esta CVE a partir do 1º comando pós-Tree-Connect
        ...

    def handle_variant_stages(self, handler, command, data, parsed):
        # lógica das stages finais (divergência real da CVE)
        ...
```

O listener da porta é compartilhado entre todas as variantes registradas
— o dispatch dinâmico decide, por conexão, qual variante trata o restante
do tráfego a partir do sinal capturado. Ver `families/smb.py` e
`families/rdp.py` para o mecanismo completo (RDP precisa de um pouco mais
de estado por conexão, já que o sinal de divergência não cabe num único
pacote — ver comentários em `families/rdp.py`).

Para uma família de protocolo nova (ex: HTTP, FTP), crie um novo módulo em
`families/` seguindo o mesmo padrão (base abstrata + listener compartilhado
+ variantes).