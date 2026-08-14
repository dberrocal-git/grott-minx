"""End-to-end smoke test: relay, framing, CRC guard, procdata and MQTT publisher.

Runs against localhost only, no external services required. Exit code 0 means
all checks passed. Run with: ``uv run python tests/test_smoke.py``.
"""

import json
import logging
import socket
import sys
import threading
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.basicConfig(level=logging.WARNING)

import grottproxy
from grottdata import MQTTPublisher, decrypt
from grottproxy import Proxy, build_ack, calc_crc

PROXY_PORT = 15888
SERVER_PORT = 15279
BROKER_PORT = 18998

FAILURES = []


def check(name, condition, detail=""):
    """Records and prints a single named check result."""
    if condition:
        print(f"PASS: {name}")
    else:
        FAILURES.append(name)
        print(f"FAIL: {name} {detail}")


def wait_for(predicate, timeout=5.0):
    """Polls until the predicate is true or the timeout expires."""
    t_end = time.time() + timeout
    while not predicate() and time.time() < t_end:
        time.sleep(0.05)
    return predicate()


def make_record(seq, rectype=0x04, total_len=600, corrupt_crc=False):
    """Builds a protocol-06 record with valid framing and CRC16-Modbus trailer."""
    datalength = total_len - 8
    payload = bytes((i * 7 + 3) % 256 for i in range(datalength - 2))
    body = seq.to_bytes(2, "big") + b"\x00\x06" + datalength.to_bytes(2, "big") + b"\x01" + bytes([rectype]) + payload
    crc = calc_crc(body) ^ (0xFFFF if corrupt_crc else 0)
    return body + crc.to_bytes(2, "big")


def make_conf(**overrides):
    """Returns a stub configuration object with the attributes the proxy expects."""
    conf = types.SimpleNamespace(
        loglevel="WARNING", grottip="127.0.0.1", grottport=PROXY_PORT,
        growattip="127.0.0.1", growattport=SERVER_PORT,
        mqttip="127.0.0.1", mqttport=1883, mqtttopic="energy/growatt",
        mqttuser="u", mqttpsw="p", mqttretain=False, nomqtt=True, inverterid="grott",
        minrecl=100, mindatarec=12, datarec=["04", "50"], smartmeterrec=["1b", "20", "1e"],
        includeall=True, gtime="server", sendbuf=False,
        blockcmd=False, noforward=False, fallback=True, fallbackretry=300,
        buffersize=64, selecttimeout=0.2, connecttimeout=5.0,
        maxpending=1048576, maxparsebuf=1048576, backlog=10,
        tcpkeepidle=60, tcpkeepintvl=10, tcpkeepcnt=3,
        mqttkeepalive=60, mqttpublishtimeout=2.0, mqttreconnectmin=1, mqttreconnectmax=30,
        recorddict={
            "T06NNNNXMIN": {
                "decrypt": {"value": "true"},
                "pvserial": {"value": 76, "length": 10, "type": "text", "divide": 10},
                "date": {"value": 136, "divide": 10},
                "pvpowerin": {"value": 162, "length": 4, "type": "num", "divide": 10},
            },
            "T06NN20": {"decrypt": {"value": "True"}, "date": {"value": 136, "divide": 10}},
        },
    )
    vars(conf).update(overrides)
    return conf


def test_utils():
    """Checks decrypt, CRC round-trip and ACK crafting helpers."""
    sample = bytes(range(30))
    dec = decrypt(sample)
    check("decrypt keeps 8-byte header and XORs body", dec[:16] == sample[:8].hex() and len(dec) == 60)
    rec = make_record(1)
    check("calc_crc round-trip", calc_crc(rec[:-2]) == int.from_bytes(rec[-2:], "big"))
    ping = make_record(2, rectype=0x16, total_len=20)
    check("build_ack echoes ping and skips type 29",
          build_ack(ping) == ping and build_ack(make_record(3, rectype=0x29, total_len=20)) is None)
    check("multi-register write (0x10) is in the blockcmd list", 0x10 in grottproxy.blocked_rectypes)


def test_relay_and_procdata():
    """Relays fragmented, corrupt and garbage data intact while decoding valid records."""
    rec_ok = make_record(1)
    rec_bad = make_record(2, corrupt_crc=True)
    garbage = b"\xff" * 20
    expected_rx = rec_ok[:50] + rec_ok[50:] + rec_bad + garbage  # == full stream

    calls = []
    orig = grottproxy.procdata
    grottproxy.procdata = lambda conf, data: (calls.append(len(data)), orig(conf, data))
    published = []
    orig_dumps = json.dumps

    import grottdata
    grottdata.json.dumps = lambda obj: (published.append(obj), orig_dumps(obj))[1]

    results = {"rx": b"", "client_got": b""}
    srv_ready, srv_done = threading.Event(), threading.Event()

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT))
        srv.listen(1)
        srv_ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            while len(results["rx"]) < len(expected_rx):
                data = conn.recv(4096)
                if not data:
                    break
                results["rx"] += data
            conn.sendall(b"ACK!")  # reverse path
            time.sleep(0.8)
        finally:
            conn.close()
            srv.close()
            srv_done.set()

    threading.Thread(target=fake_growatt, daemon=True).start()
    srv_ready.wait(10)

    conf = make_conf()
    proxy = Proxy(conf)
    check("proxy applies conf tunables", proxy.buffer_size == 64 and proxy.keepalive_opts == (60, 10, 3))
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=10)
    client.settimeout(10)
    client.sendall(rec_ok[:50])   # fragmented record, part 1
    time.sleep(0.3)
    client.sendall(rec_ok[50:])   # fragmented record, part 2
    client.sendall(rec_bad)       # valid framing, corrupted CRC
    client.sendall(garbage)       # unparseable bytes
    srv_done.wait(15)
    results["client_got"] = client.recv(4096)
    client.close()
    time.sleep(0.3)
    proxy.shutdown()
    grottproxy.procdata = orig
    grottdata.json.dumps = orig_dumps

    check("all bytes forwarded intact (fragmented + corrupt + garbage)", results["rx"] == expected_rx,
          f"rx={len(results['rx'])}/{len(expected_rx)}")
    check("server response relayed back to datalogger", results["client_got"] == b"ACK!")
    check("procdata called only for the CRC-valid record", calls == [600], f"calls={calls}")
    check("procdata produced a JSON message with device/time/values",
          len(published) == 1 and all(k in published[0] for k in ("device", "time", "values")))


def test_blockcmd():
    """Server->datalogger register commands are dropped; ACKs and uplink pass."""
    ack1 = make_record(0x11, rectype=0x04, total_len=60)
    cmd = make_record(0x12, rectype=0x18, total_len=60)  # remote "write datalogger register"
    ack2 = make_record(0x13, rectype=0x04, total_len=60)
    up = make_record(0x14, rectype=0x04, total_len=600)

    results = {"rx": b"", "client_got": b""}
    ready, done = threading.Event(), threading.Event()

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT + 1))
        srv.listen(1)
        ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            conn.sendall(ack1 + cmd + ack2)
            while len(results["rx"]) < len(up):
                data = conn.recv(4096)
                if not data:
                    break
                results["rx"] += data
            time.sleep(0.5)
        finally:
            conn.close()
            srv.close()
            done.set()

    threading.Thread(target=fake_growatt, daemon=True).start()
    ready.wait(10)

    conf = make_conf(grottport=PROXY_PORT + 1, growattport=SERVER_PORT + 1, blockcmd=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 1), timeout=10)
    client.settimeout(10)
    client.sendall(up)
    expected_down = ack1 + ack2
    t_end = time.time() + 8
    while len(results["client_got"]) < len(expected_down) and time.time() < t_end:
        try:
            chunk = client.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        results["client_got"] += chunk
    done.wait(15)
    client.close()
    time.sleep(0.3)
    proxy.shutdown()

    check("blockcmd: command record dropped, ACKs forwarded", results["client_got"] == expected_down,
          f"got={results['client_got'].hex()}")
    check("blockcmd: datalogger->server uplink untouched", results["rx"] == up)


def test_noforward():
    """Local mode: no Growatt connection, the proxy ACKs and still processes records."""
    calls = []
    orig = grottproxy.procdata
    grottproxy.procdata = lambda conf, data: calls.append(len(data))

    conf = make_conf(grottport=PROXY_PORT + 2, noforward=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 2), timeout=10)
    client.settimeout(10)

    ping = make_record(0x21, rectype=0x16, total_len=20)
    client.sendall(ping)
    echo = b""
    while len(echo) < len(ping):
        echo += client.recv(4096)
    check("noforward: ping echoed back", echo == ping)

    data_rec = make_record(0x22, rectype=0x04, total_len=600)
    expected_ack = data_rec[0:4] + b"\x00\x03" + data_rec[6:8] + b"\x47"
    expected_ack += calc_crc(expected_ack).to_bytes(2, "big")
    client.sendall(data_rec)
    ack = b""
    while len(ack) < len(expected_ack):
        ack += client.recv(4096)
    # The ACK is queued before procdata runs: wait for the proxy thread to catch up.
    wait_for(lambda: calls)
    client.close()
    time.sleep(0.3)
    proxy.shutdown()
    grottproxy.procdata = orig

    check("noforward: data record acknowledged with standard ACK", ack == expected_ack,
          f"ack={ack.hex()} expected={expected_ack.hex()}")
    check("noforward: record still processed locally", calls == [600], f"calls={calls}")


def test_growatt_down_fallback():
    """Growatt unreachable: the datalogger is served locally and MQTT keeps working."""
    calls = []
    orig = grottproxy.procdata
    grottproxy.procdata = lambda conf, data: calls.append(len(data))

    # growattport points at a closed port -> connection refused -> fallback path
    conf = make_conf(grottport=PROXY_PORT + 3, growattport=SERVER_PORT + 3, fallbackretry=2)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 3), timeout=10)
    client.settimeout(10)
    data_rec = make_record(0x31, rectype=0x04, total_len=600)
    expected_ack = data_rec[0:4] + b"\x00\x03" + data_rec[6:8] + b"\x47"
    expected_ack += calc_crc(expected_ack).to_bytes(2, "big")
    client.sendall(data_rec)
    ack = b""
    while len(ack) < len(expected_ack):
        ack += client.recv(4096)
    # The ACK is queued before procdata runs: wait for the proxy thread to catch up.
    wait_for(lambda: calls)
    check("fallback: record ACKed locally while Growatt is down", ack == expected_ack)
    check("fallback: record still processed for MQTT", calls == [600], f"calls={calls}")

    # the fallback session is recycled after fallbackretry seconds to re-attempt Growatt
    client.settimeout(8)
    try:
        closed = client.recv(4096) == b""
    except OSError:
        closed = True
    check("fallback: session recycled to re-attempt the Growatt connection", closed)

    client.close()
    time.sleep(0.3)
    proxy.shutdown()
    grottproxy.procdata = orig


def test_resync_after_trailer():
    """A record following an undeclared trailer in the same chunk is recovered."""
    rec1 = make_record(0x41, rectype=0x04, total_len=600)
    trailer = b"\xff" * 40  # no plausible header inside
    rec2 = make_record(0x42, rectype=0x04, total_len=600)
    stream = rec1 + trailer + rec2

    calls = []
    orig = grottproxy.procdata
    grottproxy.procdata = lambda conf, data: calls.append(len(data))

    conf = make_conf(grottport=PROXY_PORT + 4, noforward=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 4), timeout=10)
    client.settimeout(10)
    client.sendall(stream)
    wait_for(lambda: len(calls) >= 2)
    client.close()
    time.sleep(0.3)
    proxy.shutdown()
    grottproxy.procdata = orig

    check("scan-resync recovers the record after an unparseable trailer", calls == [600, 600], f"calls={calls}")


def test_mqtt():
    """Publishes through a fake broker and fails fast when no broker listens."""
    got = {"raw": b""}
    ready = threading.Event()

    def fake_broker():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", BROKER_PORT))
        srv.listen(1)
        ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            conn.recv(4096)                    # CONNECT
            conn.sendall(b"\x20\x02\x00\x00")  # CONNACK accepted
            t_end = time.time() + 6
            while time.time() < t_end and b"hello" not in got["raw"]:
                try:
                    data = conn.recv(4096)
                except TimeoutError:
                    break
                if not data:
                    break
                got["raw"] += data
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=fake_broker, daemon=True).start()
    ready.wait(10)
    pub = MQTTPublisher("127.0.0.1", BROKER_PORT, "grott-test")
    res = pub.publish("energy/growatt", "hello", timeout=5.0)
    time.sleep(0.3)
    pub.close()
    check("MQTT publish delivered over persistent connection",
          res and b"energy/growatt" in got["raw"] and b"hello" in got["raw"])

    t0 = time.time()
    pub2 = MQTTPublisher("127.0.0.1", BROKER_PORT + 1, "grott-test2")
    res2 = pub2.publish("t", "x", timeout=2.0)
    elapsed = time.time() - t0
    pub2.close()
    check("MQTT publish fails fast without broker", res2 is False and elapsed < 5, f"{elapsed:.2f}s")


if __name__ == "__main__":
    test_utils()
    test_relay_and_procdata()
    test_blockcmd()
    test_noforward()
    test_growatt_down_fallback()
    test_resync_after_trailer()
    test_mqtt()
    print("RESULT:", "ALL TESTS PASSED" if not FAILURES else f"FAILED: {FAILURES}")
    sys.exit(1 if FAILURES else 0)
