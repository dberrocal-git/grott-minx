"""End-to-end smoke test: relay, framing, CRC guard, procdata and MQTT publisher.

Runs against localhost only, no external services required. Exit code 0 means
all checks passed. Run with: ``uv run python tests/test_smoke.py``.
"""

import json
import logging
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
logging.basicConfig(level=logging.WARNING)

import grottdata
import grottproxy
from grottdata import MQTTPublisher, decrypt, procdata, shutdown_mqtt
from grottproxy import Proxy, build_ack, calc_crc, find_next_header

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


def make_announce(loggerid=b"KWK1CK53HV"):
    """Builds a masked, CRC-valid protocol-06 announce (type 03, 220B) carrying *loggerid*."""
    payload = loggerid + bytes(200)  # The id sits at decrypted bytes 8..17.
    datalength = 2 + len(payload)
    plain = (0x77).to_bytes(2, "big") + b"\x00\x06" + datalength.to_bytes(2, "big") + b"\x01\x03" + payload
    masked = bytes.fromhex(decrypt(plain))  # XOR is symmetric: plaintext -> wire form.
    return masked + calc_crc(masked).to_bytes(2, "big")


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
        timesync=False,
        buffersize=64, selecttimeout=0.2, connecttimeout=5.0,
        maxpending=1048576, maxparsebuf=1048576, backlog=10, idletimeout=300,
        idlebackoffmax=1800, idlebackoffmult=2.0, statsinterval=3600,
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


def test_idle_timeout_recycles_zombie_session():
    """A session whose Growatt side goes silent is recycled (zombie-session watchdog).

    Reproduces the 2026-08-15 incident: the cloud-side socket stays TCP-ESTABLISHED
    but delivers no data for hours while the datalogger keeps pinging (cloud LED on,
    yet no MQTT and no cloud data). The watchdog must close the pair after
    ``idletimeout`` seconds of server-side silence.
    """
    srv_ready = threading.Event()

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT + 5))
        srv.listen(1)
        srv_ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            while conn.recv(4096):  # Sink the datalogger's pings; never send anything back.
                pass
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=fake_growatt, daemon=True).start()
    srv_ready.wait(10)

    conf = make_conf(grottport=PROXY_PORT + 5, growattport=SERVER_PORT + 5, idletimeout=1)
    proxy = Proxy(conf)
    check("proxy picks up idletimeout", proxy.idle_timeout == 1)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 5), timeout=10)
    client.settimeout(10)
    client.sendall(make_record(0x51, rectype=0x16, total_len=20))  # ping, relayed to the fake server
    time.sleep(0.5)
    # Sanity: session alive while fresh; the watchdog only fires after idle_timeout of silence.
    check("fresh session not yet recycled", len(proxy.channel) == 2, f"channel={len(proxy.channel)}")
    # No more traffic: after ~idletimeout + one select round the pair must be closed.
    closed = wait_for(lambda: not proxy.channel, timeout=6)
    check("silent server-side socket recycled by idle watchdog", closed)
    try:
        check("datalogger side of the pair was closed too", client.recv(4096) == b"")
    except OSError:
        check("datalogger side of the pair was closed too", True)

    client.close()
    time.sleep(0.3)
    proxy.shutdown()


def test_idle_recycle_backoff():
    """Sessions recycled without any server data back off; server data resets the strikes."""
    conf = make_conf(idletimeout=300, idlebackoffmult=2.0, idlebackoffmax=1800)
    proxy = Proxy.__new__(Proxy)  # Pure-logic test: no sockets, no bind.
    proxy.channel = {}
    proxy.born = {}
    proxy.lastio = {}
    proxy.serverside = set()
    proxy.idle_strikes = {}
    proxy.idle_timeout = conf.idletimeout
    proxy.idle_backoff_max = conf.idlebackoffmax
    proxy.idle_backoff_mult = conf.idlebackoffmult

    class FakeSock:
        def __init__(self, addr):
            self.addr = addr

        def getpeername(self):
            return (self.addr, 5279)

    client = FakeSock("10.7.1.10")
    server = FakeSock("47.254.130.145")
    proxy.channel[client] = server
    proxy.channel[server] = client
    proxy.serverside.add(server)

    # Healthy session: no strikes -> plain idle_timeout.
    check("no strikes gives plain idletimeout", proxy.idle_recycle_delay(server) == 300)

    # Session recycled without a single server byte: lastio == born -> strike.
    now = time.monotonic()
    proxy.born[server] = now
    proxy.lastio[server] = now
    proxy.born[client] = now
    proxy.lastio[client] = now
    proxy.idle_strikes["10.7.1.10"] = proxy.idle_strikes.get("10.7.1.10", 0) + 1
    delay = proxy.idle_recycle_delay(server)
    check("one strike doubles the delay (with jitter)", 480 <= delay <= 720, f"delay={delay}")

    proxy.idle_strikes["10.7.1.10"] = 10  # Many strikes: capped at idlebackoffmax (+jitter).
    delay = proxy.idle_recycle_delay(server)
    check("delay capped at idlebackoffmax (+jitter)", 1440 <= delay <= 2160, f"delay={delay}")


def test_stats_line_and_session_age():
    """The periodic stats line reports counters and close_pair logs the session age."""
    srv_ready = threading.Event()

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT + 10))
        srv.listen(1)
        srv_ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=fake_growatt, daemon=True).start()
    srv_ready.wait(10)

    conf = make_conf(grottport=PROXY_PORT + 10, growattport=SERVER_PORT + 10, statsinterval=1)
    proxy = Proxy(conf)
    check("proxy picks up statsinterval", proxy.stats_interval == 1)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    records = []

    class Handler(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Handler()
    proxy_logger = logging.getLogger("grottproxy")
    old_level = proxy_logger.level
    proxy_logger.setLevel(logging.INFO)  # The stats line and session age are INFO.
    proxy_logger.addHandler(handler)
    try:
        client = socket.create_connection(("127.0.0.1", PROXY_PORT + 10), timeout=10)
        client.settimeout(10)
        client.sendall(make_record(0x61, rectype=0x16, total_len=20))
        time.sleep(0.5)
        client.close()
        # Wait for at least one stats line (interval is 1s + select pace).
        got_stats = wait_for(lambda: any(m.startswith("Stats last") for m in records), timeout=6)
        check("periodic stats line emitted", got_stats)
        stats_line = next((m for m in records if m.startswith("Stats last")), "")
        check("stats line reports sessions", "sessions=1" in stats_line, f"line={stats_line!r}")
        check("stats line reports superseded sessions and dropped MQTT messages",
              "superseded=0" in stats_line and "mqtt_dropped=0" in stats_line, f"line={stats_line!r}")
        summary = next((m for m in records if m.startswith("Session ")), "")
        check("close_pair logs one summary line with age, reason and bytes per side",
              "closed after" in summary and "closed by datalogger" in summary
              and "datalogger sent 20 B" in summary and "server sent nothing" in summary,
              f"messages={records!r}")
    finally:
        proxy_logger.removeHandler(handler)
        proxy_logger.setLevel(old_level)
        proxy.shutdown()


def test_stale_session_end_is_expected():
    """A reset on a session the datalogger already replaced is INFO; a reset of the live one is a WARNING.

    Reproduces the dominant pattern in production logs: the datalogger (e.g. after its
    daily reboot) opens a new connection without closing the old one, which is then
    reset minutes later.
    """
    srv_ready = threading.Event()
    conns = []

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT + 11))
        srv.listen(4)
        srv_ready.set()
        srv.settimeout(15)
        try:
            for _ in range(2):
                conns.append(srv.accept()[0])
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=fake_growatt, daemon=True).start()
    srv_ready.wait(10)

    conf = make_conf(grottport=PROXY_PORT + 11, growattport=SERVER_PORT + 11)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    records = []

    class Handler(logging.Handler):
        def emit(self, record):
            records.append((record.levelno, record.getMessage()))

    handler = Handler()
    proxy_logger = logging.getLogger("grottproxy")
    old_level = proxy_logger.level
    proxy_logger.setLevel(logging.INFO)
    proxy_logger.addHandler(handler)
    rst = struct.pack("ii", 1, 0)  # SO_LINGER 0: close() aborts the connection with a RST.
    try:
        old = socket.create_connection(("127.0.0.1", PROXY_PORT + 11), timeout=10)
        old.sendall(make_record(0x81, rectype=0x16, total_len=20))
        wait_for(lambda: len(proxy.channel) == 2)
        time.sleep(0.1)
        new = socket.create_connection(("127.0.0.1", PROXY_PORT + 11), timeout=10)
        wait_for(lambda: len(proxy.channel) == 4)

        old.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, rst)
        old.close()
        wait_for(lambda: len(proxy.channel) == 2)
        stale = [(lvl, m) for lvl, m in records if "stale, datalogger reconnected as" in m]
        check("reset of a replaced session logged at INFO as stale",
              len(stale) == 1 and stale[0][0] == logging.INFO, f"records={records!r}")
        check("stale session summary shows what each side sent",
              bool(stale) and "datalogger sent 20 B" in stale[0][1] and "server sent nothing" in stale[0][1])
        check("stale session counted as superseded, not as a reset",
              proxy.stats["superseded"] == 1 and proxy.stats["resets"] == 0, f"stats={proxy.stats}")

        new.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, rst)
        new.close()
        wait_for(lambda: not proxy.channel)
        faults = [(lvl, m) for lvl, m in records if "datalogger error" in m]
        check("reset of the live session logged at WARNING",
              len(faults) == 1 and faults[0][0] == logging.WARNING, f"records={records!r}")
        check("live session reset counted as a reset", proxy.stats["resets"] == 1, f"stats={proxy.stats}")
    finally:
        proxy_logger.removeHandler(handler)
        proxy_logger.setLevel(old_level)
        proxy.shutdown()
        for conn in conns:
            conn.close()


def test_timesync():
    """After an announce the proxy sets the datalogger clock (type 18, register 31)."""
    loggerid = b"KWK1CK53HV"
    announce = make_announce(loggerid)

    conf = make_conf(grottport=PROXY_PORT + 6, noforward=True, timesync=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 6), timeout=10)
    client.settimeout(10)
    client.sendall(announce)

    expected_ack = announce[0:4] + b"\x00\x03" + announce[6:8] + b"\x47"
    expected_ack += calc_crc(expected_ack).to_bytes(2, "big")
    expected_cmd_len = 8 + 10 + 20 + 2 + 2 + 19 + 2  # header+id+pad+reg+len+datetime+crc
    data = b""
    while len(data) < len(expected_ack) + expected_cmd_len:
        data += client.recv(4096)
    client.close()
    time.sleep(0.3)
    proxy.shutdown()

    ack, cmd = data[: len(expected_ack)], data[len(expected_ack) :]
    plain_cmd = decrypt(cmd[:-2])
    check("timesync: announce ACKed first", ack == expected_ack)
    check("timesync: command is type 18 with valid CRC",
          cmd[7] == 0x18 and calc_crc(cmd[:-2]) == int.from_bytes(cmd[-2:], "big"))
    check("timesync: command targets this datalogger and register 31",
          plain_cmd[16:36] == loggerid.hex() and plain_cmd[76:80] == "001f")
    check("timesync: payload carries a current datetime",
          bytes.fromhex(plain_cmd[84:88]).decode() == "20")


def test_timesync_response_withheld_from_cloud():
    """The datalogger's answer to our injected time command never reaches Growatt.

    The response (type 18) carries an undeclared encrypted trailer that must be
    swallowed too, even when it is split across TCP chunks. Everything else on the
    uplink (announce, data records) keeps flowing to the server.
    """
    loggerid = b"KWK1CK53HV"
    announce = make_announce(loggerid)

    response18 = make_record(0x0001, rectype=0x18, total_len=43)  # answer to the injected command
    trailer = b"\xff" * 796                                       # its undeclared encrypted trailer
    data_rec = make_record(0x52, rectype=0x04, total_len=600)
    expected_rx = announce + data_rec                             # what the cloud may see

    results = {"rx": b""}
    srv_ready, srv_done = threading.Event(), threading.Event()

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT + 8))
        srv.listen(1)
        srv_ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            while len(results["rx"]) < len(expected_rx):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                results["rx"] += chunk
        finally:
            conn.close()
            srv.close()
            srv_done.set()

    threading.Thread(target=fake_growatt, daemon=True).start()
    srv_ready.wait(10)

    conf = make_conf(grottport=PROXY_PORT + 8, growattport=SERVER_PORT + 8, timesync=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 8), timeout=10)
    client.settimeout(10)
    client.sendall(announce)
    wait_for(lambda: results["rx"], timeout=5)          # announce relayed raw (pre-injection)
    wait_for(lambda: proxy.timesynced, timeout=5)       # proxy injected the time command
    client.sendall(response18 + trailer[:400])          # response + first trailer chunk
    time.sleep(0.5)
    client.sendall(trailer[400:] + data_rec)            # rest of trailer, then a live data record
    wait_for(lambda: len(results["rx"]) >= len(expected_rx), timeout=5)
    srv_done.wait(15)
    client.close()
    time.sleep(0.3)
    proxy.shutdown()

    check("timesync response and its trailer withheld from the cloud", results["rx"] == expected_rx,
          f"rx={len(results['rx'])}/{len(expected_rx)}")
    check("timesync response squelched exactly once per session",
          len(proxy.squelched) == 0 and len(proxy.swallow_trailer) == 0)  # cleaned up on close
    check("answered clock sync leaves no setup trace behind", not proxy.trace)


def test_unanswered_timesync_logs_setup_trace():
    """An unanswered clock sync logs the records around it and any bytes stuck unparsed.

    Mirrors production: ping, the cloud reads datalogger registers (type 19), the
    datalogger answers, then announces; the clock set injected on the announce gets no
    type-18 answer and the datalogger drops the session ~30s later. The trace keeps the
    last records before the clock set and the first ones after it. Timing unchanged.
    """
    ping = make_record(0x01, rectype=0x16, total_len=40)
    srv_ready, answered = threading.Event(), threading.Event()

    def fake_growatt():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", SERVER_PORT + 13))
        srv.listen(1)
        srv_ready.set()
        srv.settimeout(15)
        conn, _ = srv.accept()
        conn.settimeout(15)
        try:
            got = b""
            while len(got) < len(ping):
                got += conn.recv(4096)
            conn.sendall(make_record(0x02, rectype=0x19, total_len=44) + ping)  # register read + ping echo
            answered.set()
            while conn.recv(4096):
                pass
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=fake_growatt, daemon=True).start()
    srv_ready.wait(10)
    conf = make_conf(grottport=PROXY_PORT + 13, growattport=SERVER_PORT + 13, timesync=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    records = []

    class Handler(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Handler()
    proxy_logger = logging.getLogger("grottproxy")
    old_level = proxy_logger.level
    proxy_logger.setLevel(logging.INFO)
    proxy_logger.addHandler(handler)
    try:
        client = socket.create_connection(("127.0.0.1", PROXY_PORT + 13), timeout=10)
        client.settimeout(10)
        client.sendall(ping)
        answered.wait(5)
        time.sleep(0.2)
        client.sendall(make_record(0x02, rectype=0x19, total_len=47))  # answer to the register read
        time.sleep(0.2)
        client.sendall(make_announce())
        wait_for(lambda: proxy.timesynced, timeout=5)
        client.sendall(make_record(0x53, rectype=0x04, total_len=600)[:20])  # stalls mid-record
        time.sleep(0.3)
        client.close()
        wait_for(lambda: any("setup trace" in m for m in records), timeout=5)
    finally:
        proxy_logger.removeHandler(handler)
        proxy_logger.setLevel(old_level)
        proxy.shutdown()

    line = next((m for m in records if "setup trace" in m), "")
    before, _, after = line.partition(" | ")
    check("unanswered clock sync logs the setup trace", "clock sync unanswered" in line, f"records={records!r}")
    check("setup trace shows the session start up to the announce, in order",
          [s in before for s in ("dl 16/40B", "cloud 19/44B", "cloud 16/40B", "dl 19/47B", "dl 03/220B")]
          == [True] * 5 and before.index("dl 16/40B") < before.index("dl 03/220B"), line)
    check("setup trace starts its 'after' part with the injected clock set and lists stuck bytes",
          after.startswith("+") and "proxy 18/63B" in after.split(",")[0] and "unparsed: dl 20 B" in after, line)


def test_malformed_records_dont_corrupt_stream():
    """An implausibly short record (reclength<8) is treated as noise, not an IndexError crash."""
    # protocol 0x02, datalength=1 -> reclength=7: used to raise IndexError on record[7].
    tiny = bytes([0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0xAA])
    good = make_record(0x61, rectype=0x04, total_len=600)

    calls = []
    orig = grottproxy.procdata
    grottproxy.procdata = lambda conf, data: calls.append(len(data))

    conf = make_conf(grottport=PROXY_PORT + 9, noforward=True)
    proxy = Proxy(conf)
    threading.Thread(target=proxy.main, args=(conf,), daemon=True).start()
    time.sleep(0.3)

    client = socket.create_connection(("127.0.0.1", PROXY_PORT + 9), timeout=10)
    client.settimeout(10)
    client.sendall(tiny + good)
    wait_for(lambda: calls)
    still_up = proxy.running and (client.send(b"") == 0 or True)  # send() raises if the socket died
    client.close()
    time.sleep(0.3)
    proxy.shutdown()
    grottproxy.procdata = orig

    check("tiny implausible record doesn't crash the parser", still_up)
    check("the valid record right after it is still processed", calls == [600], f"calls={calls}")


def test_resync_bounded():
    """find_next_header never scans past its window, however large the noise run is."""
    noise = b"\xff" * 100_000
    t0 = time.time()
    result = find_next_header(noise)
    elapsed = time.time() - t0
    check("find_next_header on 100KB of pure noise returns fast (bounded scan)", elapsed < 0.5, f"{elapsed:.2f}s")
    check("...and reports no plausible header found", result == -1)


def test_mqtt_publish_never_blocks_the_caller():
    """procdata() must return immediately even if the MQTT broker never responds."""
    rec = make_record(0x71, rectype=0x04, total_len=600)
    # Point at a TCP port nothing answers on: connect_async will keep retrying in the background,
    # so the publisher is never "connected" -- exactly the stuck-broker scenario being guarded against.
    conf = make_conf(nomqtt=False, mqttip="127.0.0.1", mqttport=18990, mqttpublishtimeout=30.0)
    try:
        t0 = time.time()
        procdata(conf, rec)
        elapsed = time.time() - t0
        check("procdata() with an unresponsive broker returns near-instantly (queued, not blocked)",
              elapsed < 1.0, f"{elapsed:.2f}s")
    finally:
        shutdown_mqtt()


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


def test_mqtt_outage_logged_once():
    """A broker outage logs one warning (not one per message) and the drop count on reconnect."""
    port = BROKER_PORT + 2
    records = []

    class Handler(logging.Handler):
        def emit(self, record):
            records.append((record.levelno, record.getMessage()))

    handler = Handler()
    data_logger = logging.getLogger("grottdata")
    old_level = data_logger.level
    data_logger.setLevel(logging.INFO)
    data_logger.addHandler(handler)
    stop = threading.Event()

    def fake_broker(ready):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        ready.set()
        srv.settimeout(10)
        try:
            conn, _ = srv.accept()
            conn.recv(4096)                    # CONNECT
            conn.sendall(b"\x20\x02\x00\x00")  # CONNACK accepted
            stop.wait(10)
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    pub = MQTTPublisher("127.0.0.1", port, "grott-outage", reconnect_min=1, reconnect_max=1)
    try:
        results = [pub.publish("t", "x", timeout=0.3) for _ in range(3)]
        warnings = [m for lvl, m in records if lvl == logging.WARNING and "not connected" in m]
        check("MQTT outage: every message dropped, a single warning logged",
              results == [False] * 3 and len(warnings) == 1, f"records={records!r}")

        ready = threading.Event()
        threading.Thread(target=fake_broker, args=(ready,), daemon=True).start()
        ready.wait(5)
        reconnected = wait_for(
            lambda: any("3 message(s) dropped while disconnected" in m for _, m in records), timeout=8
        )
        check("MQTT reconnect reports how many messages were dropped", reconnected, f"records={records!r}")
    finally:
        stop.set()
        pub.close()
        data_logger.removeHandler(handler)
        data_logger.setLevel(old_level)


def test_publish_stats_counters():
    """The stats line reads delivered and dropped MQTT messages separately, and resets them."""
    grottdata.take_publish_stats()
    grottdata._count_publish("published")
    grottdata._count_publish("dropped")
    grottdata._count_publish("dropped")
    check("publish counters report (published, dropped) and reset on read",
          grottdata.take_publish_stats() == (1, 2) and grottdata.take_publish_stats() == (0, 0))


def test_sigterm_clean_shutdown():
    """SIGTERM (service stop/restart) shuts down cleanly and says so in the log."""
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as tmp:
        # noforward: the readiness probe below must never reach the real Growatt server.
        Path(tmp, "grott.ini").write_text(
            f"[Generic]\ngrottip = 127.0.0.1\ngrottport = {PROXY_PORT + 12}\n"
            "[Growatt]\nnoforward = True\n[MQTT]\nnomqtt = True\n"
        )
        proc = subprocess.Popen(
            [sys.executable, str(repo / "grott.py")], cwd=tmp,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            listening = wait_for(lambda: _port_open(PROXY_PORT + 12), timeout=10)
            proc.send_signal(signal.SIGTERM)
            out, _ = proc.communicate(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
    check("SIGTERM: proxy was up before the signal", listening)
    check("SIGTERM: exits cleanly and logs why",
          proc.returncode == 0 and "stopped by SIGTERM" in out and "Grott proxy stopped" in out,
          f"rc={proc.returncode} out={out!r}")


def _port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    test_utils()
    test_relay_and_procdata()
    test_blockcmd()
    test_noforward()
    test_growatt_down_fallback()
    test_resync_after_trailer()
    test_idle_timeout_recycles_zombie_session()
    test_idle_recycle_backoff()
    test_stats_line_and_session_age()
    test_stale_session_end_is_expected()
    test_timesync()
    test_timesync_response_withheld_from_cloud()
    test_unanswered_timesync_logs_setup_trace()
    test_malformed_records_dont_corrupt_stream()
    test_resync_bounded()
    test_mqtt_publish_never_blocks_the_caller()
    test_mqtt()
    test_mqtt_outage_logged_once()
    test_publish_stats_counters()
    test_sigterm_clean_shutdown()
    print("RESULT:", "ALL TESTS PASSED" if not FAILURES else f"FAILED: {FAILURES}")
    sys.exit(1 if FAILURES else 0)
