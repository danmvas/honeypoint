#!/usr/bin/env python3
"""
Honeypoint Framework — Family Dispatch (genérico, sem protocolo)
====================================================================
Infraestrutura genérica para famílias de driver: múltiplas variantes
(CVEs) de um mesmo protocolo compartilhando uma única porta TCP, com
resolução dinâmica de qual variante trata cada conexão.

Este módulo não sabe nada sobre SMB, RDP, ou qualquer protocolo
específico. Apenas orquestra sockets, threads e o registro de variantes
por porta. É o mesmo papel que `framework/launcher.py` já cumpre para
"um driver, uma porta, sempre ligado"; aqui é "múltiplos drivers
relacionados, uma porta compartilhada, decisão em tempo de conexão".

Uso por uma família de protocolo (ex: `families/smb.py`):

    class SMBFamilyDriver(FamilyDriver):
        _listener_cls = _SMBPortListener  # PortListener específico do protocolo

        def matches_variant(self, ...): ...
        def handle_variant_stages(self, ...): ...

    class _SMBPortListener(PortListener):
        def _create_handler(self, sock, addr):
            return SMBConnectionHandler(self, sock, addr)

Os métodos `matches_variant()`/`handle_variant_stages()` ficam com
assinatura genérica aqui. Cada família redeclara com os parâmetros
específicos do seu protocolo (documentação/clareza), mas a decisão de
"qual variante trata esta conexão" e o transporte (bind/accept/threads)
são inteiramente genéricos.
"""

import logging
import socket
import threading
import time
from builtins import NotImplementedError
from typing import Optional

from framework.base import HoneyPointDriver
from framework.tracker import SCTracker

logger = logging.getLogger("honeypoint.family")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _sh = logging.StreamHandler()
    _sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(_sh)


class FamilyDriver(HoneyPointDriver):
    """Base genérica para drivers que simulam CVEs de uma mesma família
    de protocolo, compartilhando porta com outras variantes.

    Subclasses de protocolo (ex: `families.smb.SMBFamilyDriver`) devem
    definir `_listener_cls` apontando para o `PortListener` específico
    do protocolo, e deixar `matches_variant()`/`handle_variant_stages()`
    para os drivers-folha (CVE específica) implementarem.
    """

    # Registro compartilhado por TODAS as famílias e variantes — é isso
    # que permite duas CVEs diferentes (mesmo de famílias distintas, já
    # que a chave é a porta) dividirem um listener.
    _listeners: dict[int, "PortListener"] = {}
    _listeners_lock = threading.Lock()

    # Definido por cada família de protocolo (ex: _SMBPortListener, _RDPPortListener)
    _listener_cls: type["PortListener"]

    def __init__(self):
        self._tracker: Optional[SCTracker] = None
        self._bound_port: Optional[int] = None

    def is_default_variant(self) -> bool:
        """True para a variante que trata conexões cujo sinal não bate
        com nenhuma CVE específica registrada na mesma porta (fallback).
        Exatamente uma variante por porta deve retornar True."""
        return False

    def matches_variant(self, *args, **kwargs) -> bool:
        """Decide, a partir do sinal capturado (específico do
        protocolo — ver a família concreta), se esta variante deve
        tratar o resto da conexão."""
        raise NotImplementedError

    def handle_variant_stages(self, handler, *args, **kwargs):
        """Trata os eventos a partir do ponto de divergência — aqui
        vive a lógica específica da CVE (stages finais)."""
        raise NotImplementedError

    def start(self, port: int, tracker: SCTracker) -> None:
        self._tracker = tracker
        self._bound_port = port
        with FamilyDriver._listeners_lock:
            listener = FamilyDriver._listeners.get(port)
            is_owner = listener is None
            if is_owner:
                listener = self._listener_cls(port)
                FamilyDriver._listeners[port] = listener
            listener.register_variant(self)

        if is_owner:
            listener.run()
        else:
            listener.wait_until_stopped()

    def stop(self) -> None:
        listener = FamilyDriver._listeners.get(self._bound_port)
        if listener:
            listener.stop()


class PortListener:
    """Um único socket TCP compartilhado por todas as variantes
    (drivers) de uma família registradas na mesma porta.

    Subclasses de protocolo só precisam implementar `_create_handler()`
    — todo o resto (bind/listen/accept loop, registro de variantes,
    período de graça, parada) é genérico.
    """

    REGISTRATION_GRACE_SECONDS = 0.3

    def __init__(self, port: int):
        self.port = port
        self.variants: list[FamilyDriver] = []
        self.default_variant: Optional[FamilyDriver] = None
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._stopped_event = threading.Event()

    def _create_handler(self, sock: socket.socket, addr: tuple):
        """Retorna uma instância do ConnectionHandler específico do
        protocolo para uma conexão recém-aceita."""
        raise NotImplementedError

    def register_variant(self, variant: FamilyDriver) -> None:
        self.variants.append(variant)
        if variant.is_default_variant():
            self.default_variant = variant

    def effective_default_variant(self) -> FamilyDriver:
        return self.default_variant or self.variants[0]

    def wait_until_stopped(self) -> None:
        self._stopped_event.wait()

    def run(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self.port))
        self._sock.listen(10)
        self._running = True
        logger.info(f"🍯 Family Honeypoint escutando na porta {self.port}")

        # As threads dos drivers sobem quase simultaneamente no launcher,
        # mas sem garantia de ordem — uma pequena janela evita aceitar a
        # primeira conexão antes de todas as variantes se registrarem.
        time.sleep(self.REGISTRATION_GRACE_SECONDS)
        names = [v.get_metadata().name for v in self.variants]
        logger.info(f"🍯 Variantes ativas na porta {self.port}: {names}")

        while self._running:
            try:
                self._sock.settimeout(1.0)
                try:
                    client_sock, addr = self._sock.accept()
                except socket.timeout:
                    continue
                handler = self._create_handler(client_sock, addr)
                t = threading.Thread(target=handler.handle, daemon=True,
                                     name=f"family-{addr[0]}:{addr[1]}")
                t.start()
            except OSError:
                break
        self._stopped_event.set()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            self._sock.close()
        self._stopped_event.set()
