# Honeypoint Drivers

## Como criar um novo driver

Um driver é um módulo Python que implementa a simulação de um protocolo específico para enganar um scanner de reconhecimento.

### 1. Crie o arquivo em `drivers/`

```python
# drivers/meu_protocolo.py
from framework import HoneyPointDriver, DriverMetadata, StageDefinition, SCTracker

class MeuProtocoloDriver(HoneyPointDriver):
    
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