# STAGED Families

`families/` é a camada entre `framework/` (core genérico, sem protocolo) e
`drivers/` (CVE específica): concentra o **tronco de reconhecimento
compartilhado** por CVEs relacionadas de um mesmo protocolo.

```
framework/   ← core genérico — não sabe de protocolo nem de famílias específicas
              (framework/family.py: orquestração genérica de múltiplas
               variantes dividindo uma porta — também não sabe de protocolo)
families/    ← tronco de protocolo compartilhado (SMB1-Recon, RDP-Recon, ...)
drivers/     ← CVE específica (arquivo fino, só a divergência real)
```

Por que essa camada existe: várias CVEs do mesmo protocolo começam o
reconhecimento exatamente da mesma forma (ex: qualquer scanner SMBv1 faz
Negotiate → Session Setup → Tree Connect IPC$ antes de chegar no teste
específico da vulnerabilidade). Sem `families/`, cada driver reimplementaria
esse trecho do zero — foi o que aconteceu antes da família SMB ser extraída
(`eternalblue.py` caiu de 537 para ~90 linhas quando o tronco compartilhado
saiu de dentro dele).

## Famílias existentes

| Família | Módulo | Stages compartilhadas | Drivers |
|---|---|---|---|
| SMB1-Recon | `families/smb.py` (`SMBFamilyDriver`) | Negotiate, Session Setup, Tree Connect IPC$ | `drivers/eternalblue.py` |
| RDP-Recon | `families/rdp.py` (`RDPFamilyDriver`) | X.224 Connection Request, Security Negotiation, MCS Connect Initial | `drivers/bluekeep.py`, `drivers/ms12_020.py` |

`SMB1-Recon` tem só um membro por enquanto — não existe, nas ferramentas que
este projeto usa (Metasploit `auxiliary/scanner/`, nmap `vuln`), um segundo
scanner de reconhecimento seguro e dedicado para outra CVE SMBv1 (ver
`README.md` raiz para o que foi avaliado e por que foi descartado). A base já
está pronta para quando uma CVE assim for encontrada.

## Como o dispatch dinâmico funciona (genérico, `framework/family.py`)

- Todas as variantes (drivers) de uma família registradas na mesma porta
  compartilham um único `PortListener` — só a primeira a chegar de fato dá
  `bind()`/`listen()` no socket; as demais só se registram como candidatas
  (`FamilyDriver.start()`).
- O `ConnectionHandler` específico do protocolo trata as stages
  compartilhadas uma única vez por conexão e bufferiza os eventos.
- No ponto em que o sinal de divergência aparece (varia por protocolo — ver
  abaixo), cada variante registrada é consultada via `matches_variant()`; a
  primeira que reconhecer o sinal "recebe" a conexão — os eventos
  bufferizados são reproduzidos num `SCTracker` só daquela conexão
  (`tracker.fork()` do tracker da variante, com IP e porta de origem), e o
  restante da conexão é delegado a `handle_variant_stages()`.
- Se nenhuma variante reconhecer o sinal, a variante marcada como
  `is_default_variant()` trata a conexão (fallback).
- Uma conexão que termina **antes** do ponto de divergência só exercitou o
  tronco: é registrada sob a família (`PortListener.unresolved_tracker()`,
  ex. `sc_RDP-Recon_*.json`), não sob a variante default.

O ponto em que o sinal fica claro **não é igual em toda família**:

- **SMB1-Recon**: um único comando pós-Tree-Connect já basta
  (`matches_variant(command, parsed)`).
- **RDP-Recon**: o sinal só fica claro depois de uma sequência curta de PDUs
  MCS — por isso `RDPConnectionHandler` mantém um pequeno estado de sessão
  (IDs de usuário já alocados, canais estáticos do CS_NET) e consulta as
  variantes a cada Attach User Request (o MS12-020 se revela no 2º) e no
  primeiro Channel Join Request, passando esse estado (`context`) para
  `matches_variant()`/`handle_variant_stages()` em vez de só
  `(command, parsed)`. Depois dos Channel Joins, a família conduz a
  sequência de conexão RDP (Security Exchange, licença, Demand Active,
  finalização) e entrega às variantes os dados dos canais virtuais
  (evento `"channel_data"`).

Isso é o "attach" dinâmico ao driver certo assim que a família é reconhecida
— sem exigir dois sockets na mesma porta, e sem o launcher (`framework/
launcher.py`) precisar saber que existe mais de um driver ali.

## Como criar uma família nova

1. Crie `families/<protocolo>.py`.
2. Defina `SHARED_<PROTO>_STAGES: list[StageDefinition]` com as etapas
   idênticas entre as CVEs do protocolo.
3. Implemente o `ConnectionHandler` específico (parsers/builders do
   protocolo + lógica de buffering das stages compartilhadas + resolução de
   variante) — usar `families/smb.py` (sinal de um pacote só) ou
   `families/rdp.py` (sinal de múltiplos pacotes) como referência, conforme
   o protocolo alvo se pareça mais com um ou outro caso.
4. Implemente um `_<Proto>PortListener(framework.family.PortListener)` que só
   precisa de `_create_handler(sock, addr)` retornando seu ConnectionHandler.
5. Implemente um `<Proto>FamilyDriver(framework.family.FamilyDriver)` com
   `_listener_cls = _<Proto>PortListener` e redeclare
   `matches_variant()`/`handle_variant_stages()` com os parâmetros
   específicos do protocolo (documentação — tecnicamente já vêm herdados
   como abstratos de `framework.family.FamilyDriver`).

Para adicionar uma CVE a uma família já existente, veja `drivers/README.md`.

## Regra crítica: import qualificado

Sempre importe o **módulo**, nunca a classe diretamente:

```python
from families import smb          # certo
from families.smb import SMBFamilyDriver   # ERRADO — quebra a descoberta
```

`framework/launcher.py.discover_drivers()` inspeciona todo nome de classe
visível no namespace do módulo do driver, não só as definidas nele. Se
`SMBFamilyDriver` (ou `FamilyDriver`/`PortListener`) vazar para o namespace
de um driver via `from ... import Classe`, o launcher tenta instanciá-la
como se fosse um driver de verdade e quebra a descoberta. Importar o módulo
qualificado (`smb.SMBFamilyDriver`) evita isso, porque um módulo falha o
teste `inspect.isclass()` antes de qualquer `issubclass()` ser avaliado.
