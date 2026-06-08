# Core do Honeypoint Framework

Este diretório contém o **core genérico** do framework. Ele provê toda a infraestrutura necessária para criar, executar e avaliar honeypoints, sem saber nada sobre protocolos específicos.

**Este código não deve ser modificado para adicionar suporte a novos protocolos ou CVEs.** Para isso, crie um novo driver em `drivers/`. Veja `drivers/README.md`.

---

## Componentes

### `base.py` — Contrato do driver

Define as classes que todo driver deve usar:

- **`HoneyPointDriver`** — classe base abstrata. Todo driver herda dela e implementa três métodos: `get_metadata()`, `start()` e `stop()`.
- **`DriverMetadata`** — dataclass que descreve o driver: nome, CVE, protocolo, porta padrão, scanner esperado, e a lista de stages.
- **`StageDefinition`** — dataclass que define uma etapa do protocolo de reconhecimento: número, nome, descrição e camada de protocolo.

### `tracker.py` — Stage Coverage

Rastreia a progressão de um scanner pelas etapas do protocolo e calcula a métrica SC.

- **`SCTracker`** — instanciado pelo launcher a partir do `DriverMetadata` do driver. O driver chama `tracker.complete_stage(n, ...)` conforme o scanner progride. Ao final, `tracker.finalize_session()` salva um JSON com todos os dados da sessão.
- Cada sessão gera um arquivo `sc_<driver>_<timestamp>.json` em `/var/log/honeypoint/`.

O tracker é genérico — ele não sabe se está rastreando SMB, RDP, ou qualquer outro protocolo. Ele recebe o total de stages do driver e conta quantas foram completadas.

### `launcher.py` — Discovery e execução

Descobre automaticamente todos os drivers em `drivers/`, instancia e executa em threads separadas.

- Percorre `drivers/*.py`, importa cada módulo, e coleta classes que herdam de `HoneyPointDriver`.
- Cria um `SCTracker` para cada driver a partir do seu `DriverMetadata`.
- Suporta execução de todos os drivers simultaneamente ou de um driver específico via `--driver`.

---

## Por que não modificar o core?

A separação entre framework e drivers é a contribuição arquitetural central da dissertação. O framework é análogo ao motor de um IDS (Snort/Suricata): ele provê a infraestrutura genérica, e o usuário cria "assinaturas" (drivers) para os protocolos que deseja simular.

Se a lógica de um protocolo específico estiver dentro do framework, a arquitetura perde sua generalidade e o argumento acadêmico enfraquece. Toda lógica que depende de um protocolo (parsing de pacotes, construção de respostas, handshake) pertence ao driver correspondente em `drivers/`.

---

## API para drivers

```python
from framework import HoneyPointDriver, DriverMetadata, StageDefinition, SCTracker

class MeuDriver(HoneyPointDriver):

    def get_metadata(self) -> DriverMetadata:
        return DriverMetadata(
            name="MeuProtocolo",
            cve="CVE-XXXX-XXXX",
            cve_alias="Nome",
            protocol="PROTO",
            default_port=9999,
            scanner_module="auxiliary/scanner/...",
            scanner_tool="Metasploit Framework",
            description="...",
            stages=[
                StageDefinition(1, "Handshake", "...", "PROTO"),
                StageDefinition(2, "Negotiate", "...", "PROTO"),
            ]
        )

    def start(self, port: int, tracker: SCTracker) -> None:
        # O tracker já foi criado pelo launcher.
        # Use tracker.new_session(source_ip=...) para cada conexão.
        # Use tracker.complete_stage(n, "nome", data={...}) para cada etapa.
        # Use tracker.finalize_session(deception_success=True) ao final.
        ...

    def stop(self) -> None:
        ...
```