"""Exercise the real DNS TCP client against isolated, synthetic loopback peers."""
import socket
import struct
import subprocess
import sys
import threading
import time

PROBE = sys.argv[1]
IP = bytes([192, 0, 2, 42])


def name(value):
    return b"".join(bytes([len(part)]) + part.encode() for part in value.split(".")) + b"\0"


def rr(owner=b"\xc0\x0c", kind=1, data=IP, cls=1):
    return owner + struct.pack("!HHIH", kind, cls, 60, len(data)) + data


def reply(query, records=None, flags=0x8180, question=None):
    records = [rr()] if records is None else records
    return query[:2] + struct.pack("!HHHHH", flags, 1, len(records), 0, 0) + (query[12:] if question is None else question) + b"".join(records)


def receive(peer, size):
    result = b""
    while len(result) < size:
        part = peer.recv(size - len(result))
        if not part:
            raise AssertionError("query ended early")
        result += part
    return result


def check(label, make_reply, success=False, output=None, mode="normal", host="vpn.example.test"):
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(2)

        def serve():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(2)
                    size = struct.unpack("!H", receive(peer, 2))[0]
                    query = receive(peer, size)
                    assert query[2:12] == b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    assert query[12:] == name("vpn.example.test") + b"\x00\x01\x00\x01"
                    packet = make_reply(query)
                    framed = struct.pack("!H", len(packet)) + packet
                    if mode == "timeout":
                        # Client must close on its deadline while a partial frame is pending.
                        peer.sendall(framed[:1])
                        assert peer.recv(1) == b""
                    elif mode == "short":
                        peer.sendall(framed[:-1])
                    elif mode == "split":
                        for byte in framed:
                            peer.sendall(bytes([byte]))
                    else:
                        peer.sendall(framed)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        started = time.monotonic()
        process = subprocess.run([PROBE, host, str(listener.getsockname()[1]), "200"], capture_output=True, text=True, timeout=3)
        elapsed = time.monotonic() - started
        worker.join(3)
        assert not worker.is_alive(), label
        if errors:
            raise errors[0]
        assert (process.returncode == 0) == success, (label, process.stdout, process.stderr)
        if output:
            assert process.stdout.strip() == output, (label, process.stdout)
        if mode == "timeout":
            assert elapsed < 1.5, (label, elapsed)
        print("PASS", label)


check("compressed A / split TCP frames", reply, True, "192.0.2.42", "split")
check("case and terminal dot", reply, True, "192.0.2.42", host="VPN.Example.Test.")
check("benchmark result is accepted", lambda q: reply(q, [rr(data=bytes([198, 18, 2, 222]))]), True, "198.18.2.222")
check("CNAME chain with reordered answers", lambda q: reply(q, [rr(name("edge.example.test")), rr(kind=5, data=name("edge.example.test"))]), True, "192.0.2.42")
check("private gateway", lambda q: reply(q, [rr(data=bytes([10, 2, 3, 4]))]), True, "10.2.3.4")
check("wrong transaction", lambda q: b"\xff\xff" + reply(q)[2:] if q[:2] != b"\xff\xff" else b"\x00\x00" + reply(q)[2:])
for flags in [0x0180, 0x8980, 0x8380, 0x8183, 0x8182]:
    check(f"reject flags {flags:x}", lambda q, f=flags: reply(q, flags=f))
check("wrong question", lambda q: reply(q, question=name("other.example.test") + b"\0\1\0\1"))
check("wrong question type", lambda q: reply(q, question=q[12:-4] + b"\0\x1c\0\1"))
check("unrelated answer", lambda q: reply(q, [rr(name("other.example.test"))]))
check("empty answer", lambda q: reply(q, []))
check("wrong class", lambda q: reply(q, [rr(cls=3)]))
check("wrong address length", lambda q: reply(q, [rr(data=IP[:3])]))
check("malformed record after valid A", lambda q: reply(q, [rr(), rr()[:-1]]))
check("CNAME with trailing bytes", lambda q: reply(q, [rr(kind=5, data=name("edge.example.test") + b"x")]))
check("CNAME loop", lambda q: reply(q, [rr(kind=5, data=b"\xc0\x0c")]))
check("compression loop", lambda q: reply(q, [rr(owner=bytes([0xc0 | ((len(q) >> 8) & 0x3f), len(q) & 0xff]))]))
check("out of bounds pointer", lambda q: reply(q, [rr(owner=b"\xff\xff")]))
check("oversized response", lambda q: b"x" * 4097)
check("truncated frame", reply, mode="short")
check("deadline covers partial frame", reply, mode="timeout")

for host in ["vpn..example.test", "vpn.example.test..", "x" * 64 + ".test", "a\nb.test", ""]:
    result = subprocess.run([PROBE, host, "1", "200"], capture_output=True, text=True, timeout=3)
    assert result.returncode == 1 and "Invalid gateway DNS name" in result.stdout, (host, result.stdout, result.stderr)
print("PASS invalid names rejected before network access")

if len(sys.argv) > 2:
    engine = sys.argv[2]
    accepted = subprocess.run([engine, "--gateway-dns=223.5.5.5", "--capabilities-json"], capture_output=True, text=True, timeout=3)
    assert accepted.returncode == 0, accepted.stderr
    for dns in ["dns.test", "224.0.0.1", "1.1.1.1:53", ""]:
        rejected = subprocess.run([engine, f"--gateway-dns={dns}", "--capabilities-json"], capture_output=True, text=True, timeout=3)
        assert rejected.returncode != 0 and "gateway-dns must be" in rejected.stderr + rejected.stdout
    print("PASS CLI validates explicit DNS without root or tunnel launch")
