# T5 - inert socket, verbatim from RUNBOOK.md section 1 (accept, never answer).
import socket, threading
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(32)
    while True:
        c, _ = s.accept(); threading.Timer(30, c.close).start()   # accept, never answer
for p in (445, 3389):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
