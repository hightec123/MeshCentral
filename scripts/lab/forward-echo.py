"""Disposable loopback fixture. Echo bytes unchanged over TCP and UDP."""
import selectors
import socket
import sys
import time

with selectors.DefaultSelector() as selector, socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
    tcp.bind((sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1", 0))
    host, port = tcp.getsockname()
    udp.bind((host, port))
    other.bind((host, 0))
    tcp.listen()
    selector.register(tcp, selectors.EVENT_READ)
    selector.register(udp, selectors.EVENT_READ)
    print(port, flush=True)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        for key, _ in selector.select(timeout=1):
            sock = key.fileobj
            if sock is tcp:
                client, _ = tcp.accept()
                client.settimeout(3)
                selector.register(client, selectors.EVENT_READ)
            elif sock is udp:
                payload, peer = udp.recvfrom(65507)
                other.sendto(b"unexpected source", peer)
                udp.sendto(payload, peer)
            else:
                try:
                    payload = sock.recv(32768)
                    if payload:
                        sock.sendall(payload)
                        continue
                except (OSError, TimeoutError):
                    pass
                selector.unregister(sock)
                sock.close()
