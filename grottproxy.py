"""Transparent TCP proxy between Growatt dataloggers and the Growatt cloud."""

import logging
import select
import socket
import time
from signal import SIG_DFL, SIGPIPE, signal

from grottdata import format_multi_line, procdata

logger = logging.getLogger(__name__)

known_protocols = (0x00, 0x02, 0x05, 0x06)
# Register read/write record types the Growatt server may send towards the datalogger/inverter.
blocked_rectypes = (0x05, 0x06, 0x10, 0x18, 0x19)


def calc_crc(data):
    """Calculates the CRC16-Modbus checksum of the given bytes.

    Args:
        data: Bytes to checksum.

    Returns:
        The checksum as an int.
    """
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for _ in range(8):
            if (crc & 1) != 0:
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return crc


def build_ack(record):
    """Crafts the acknowledge the Growatt server would send (local/no-forward modes).

    Args:
        record: One complete, CRC-valid record.

    Returns:
        The acknowledge bytes, or None for record types the real server never
        answers (type ``29``). Pings (type ``16``) are acknowledged by echo.
    """
    rectype = record[7]
    if rectype == 0x16:
        return record
    if rectype == 0x29:
        return None
    # Layout: seq + protocol + length(=3: deviceno, rectype, ack byte) + deviceno + rectype.
    prefix = record[0:4] + (3).to_bytes(2, "big") + record[6:8]
    if record[3] in (0x05, 0x06):
        ack = prefix + b"\x47"  # Ack byte 0x00 XOR-masked with the "G" of "Growatt".
        return ack + calc_crc(ack).to_bytes(2, "big")
    return prefix + b"\x00"


def set_keepalive(sock, idle, interval, count):
    """Enables TCP keepalive so dead peers are detected and cleaned up.

    Args:
        sock: Socket to configure.
        idle: Seconds of inactivity before the first probe.
        interval: Seconds between probes.
        count: Number of failed probes before the connection is dropped.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
    except OSError as e:
        logger.debug("Could not enable TCP keepalive: %s", e)


class Forward:
    """Outgoing connection towards the Growatt server."""

    def __init__(self):
        """Creates the TCP socket (not yet connected)."""
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port, timeout):
        """Opens the forward connection with a bounded connect timeout.

        Args:
            host: Growatt server address.
            port: Growatt server port.
            timeout: Maximum seconds for the connect attempt.

        Returns:
            The connected socket, or False when the server is unreachable.
        """
        try:
            self.forward.settimeout(timeout)
            self.forward.connect((host, port))
            self.forward.settimeout(None)
            return self.forward
        except Exception as e:
            logger.error("Proxy forward error, Growatt server %s:%s unreachable : %s", host, port, e)
            try:
                self.forward.close()
            except OSError:
                pass
            return False


class Proxy:
    """Transparent Growatt proxy.

    Robustness design:

    - Relay sockets are non-blocking: a slow or dead peer can never freeze the loop.
    - Passthrough is decoupled from parsing: every byte received is always forwarded,
      even when a record cannot be parsed locally.
    - Partial TCP fragments are buffered per connection until the record is complete.
    - Outbound data is queued per socket and flushed when the socket is writable.
    - Record processing (MQTT) runs guarded: a bad record never stops the relay.

    Optional modes:

    - blockcmd: the server->datalogger direction is forwarded per record, dropping
      remote register commands (blocked_rectypes); unparseable streams are forwarded
      raw (fail open).
    - noforward: fully local, no Growatt connection; the proxy acknowledges records.
    - Offline fallback (default on): when Growatt is unreachable the datalogger is
      served in local-ACK mode so MQTT keeps flowing; the session is recycled every
      ``fallbackretry`` seconds to re-attempt the cloud connection.
    """

    def __init__(self, conf):
        """Binds the listen socket and loads the operational tunables from *conf*."""
        logger.info("grott-minx proxy mode started")

        # Restore default SIGPIPE so a closed peer cannot raise errno 32.
        signal(SIGPIPE, SIG_DFL)

        self.running = True
        self.input_list = []  # Sockets watched for input.
        self.channel = {}     # Socket <-> peer socket (peer is None for locally-served connections).
        self.recvbuf = {}     # Per-socket (possibly partial) record parse buffer.
        self.sendbuf = {}     # Per-socket outbound queue.
        self.serverside = set()  # Sockets connected to the Growatt server.
        self.fallback_deadline = {}  # Fallback socket -> monotonic time to retry Growatt.
        self.lastrec = {}  # Socket -> (rectype, protocol, length) of the last parsed record.

        self.blockcmd = conf.blockcmd
        self.noforward = conf.noforward
        self.fallback_enabled = conf.fallback
        self.fallback_retry = conf.fallbackretry

        # Operational tuning (grott.ini [Proxy] section).
        self.buffer_size = conf.buffersize
        self.select_timeout = conf.selecttimeout
        self.connect_timeout = conf.connecttimeout
        self.max_pending = conf.maxpending
        self.max_parsebuf = conf.maxparsebuf
        self.keepalive_opts = (conf.tcpkeepidle, conf.tcpkeepintvl, conf.tcpkeepcnt)

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((conf.grottip, conf.grottport))
        try:
            hostname = socket.gethostname()
            logger.info("\t - Hostname : %s", hostname)
            testip = socket.gethostbyname(hostname)
            logger.info("\t - IP : %s, port : %s", testip, conf.grottport)
        except Exception as e:
            logger.warning("IP and port information not available: %s", e)

        self.server.listen(conf.backlog)
        self.forward_to = (conf.growattip, conf.growattport)

    def main(self, conf):
        """Runs the relay loop until shutdown; unexpected errors never stop it."""
        self.input_list.append(self.server)
        while self.running:
            try:
                self._serve_once(conf)
            except Exception:
                # KeyboardInterrupt is BaseException and still propagates.
                logger.exception("Unexpected proxy error, proxy keeps running")

    def _serve_once(self, conf):
        """Performs one select() round: expiries, pending sends, accepts and reads."""
        # Recycle fallback sessions so the Growatt connection is re-attempted periodically.
        if self.fallback_deadline:
            now = time.monotonic()
            for sock in list(self.fallback_deadline):
                if now >= self.fallback_deadline.get(sock, now + 1):
                    logger.info("Recycling local fallback session to re-attempt the Growatt connection")
                    self.close_pair(sock)

        writelist = [sock for sock, pending in self.sendbuf.items() if pending]
        try:
            readready, writeready, exceptready = select.select(
                self.input_list, writelist, self.input_list, self.select_timeout
            )
        except (OSError, ValueError):
            self._drop_dead_sockets()
            return

        for sock in writeready:
            if sock in self.sendbuf:
                self.flush(sock)

        for sock in exceptready:
            if sock is not self.server and sock in self.channel:
                logger.warning("Socket exception condition, closing connection pair")
                self.close_pair(sock)

        for sock in readready:
            if sock is self.server:
                self.on_accept()
            elif sock in self.channel:
                self.on_read(sock, conf)

    def _drop_dead_sockets(self):
        """Removes invalid sockets after select() rejects the watch lists."""
        for sock in list(self.channel):
            try:
                dead = sock.fileno() == -1
            except OSError:
                dead = True
            if dead:
                self.close_pair(sock)

    def _register_local(self, sock):
        """Registers a datalogger connection served locally (no Growatt peer)."""
        sock.setblocking(False)
        set_keepalive(sock, *self.keepalive_opts)
        self.input_list.append(sock)
        self.recvbuf[sock] = b""
        self.sendbuf[sock] = b""
        self.channel[sock] = None

    def on_accept(self):
        """Accepts a datalogger connection and opens its Growatt counterpart.

        Falls back to a locally-served session when Growatt is unreachable and
        fallback is enabled; otherwise the client connection is refused.
        """
        try:
            clientsock, clientaddr = self.server.accept()
        except OSError as e:
            if self.running:  # During shutdown the listen socket is closed on purpose.
                logger.warning("Accept failed: %s", e)
            return

        if self.noforward:
            logger.info("Client connection from: %s (local mode, Growatt not contacted)", clientaddr)
            self._register_local(clientsock)
            return

        forward = Forward().start(self.forward_to[0], self.forward_to[1], self.connect_timeout)
        if not forward:
            if not self.fallback_enabled:
                logger.warning("Can't establish connection with remote server")
                logger.warning("Closing connection with client side: %s", clientaddr)
                try:
                    clientsock.close()
                except OSError:
                    pass
                return
            logger.warning(
                "Growatt server unreachable, serving %s in local fallback mode "
                "(records ACKed locally, published to MQTT only); retry in %ss",
                clientaddr, self.fallback_retry,
            )
            self._register_local(clientsock)
            self.fallback_deadline[clientsock] = time.monotonic() + self.fallback_retry
            return

        logger.info("Client connection from: %s", clientaddr)
        for sock in (clientsock, forward):
            sock.setblocking(False)
            set_keepalive(sock, *self.keepalive_opts)
            self.input_list.append(sock)
            self.recvbuf[sock] = b""
            self.sendbuf[sock] = b""
        self.channel[clientsock] = forward
        self.channel[forward] = clientsock
        self.serverside.add(forward)

    def on_read(self, sock, conf):
        """Reads available data, forwards it and feeds the record parser."""
        try:
            data = sock.recv(self.buffer_size)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as e:
            logger.warning("Connection error: %s", e)
            self.close_pair(sock)
            return

        if not data:
            self.close_pair(sock)
            return

        if sock not in self.channel:
            return
        peer = self.channel[sock]

        # Raw passthrough, unless this direction is command-filtered (then forwarded per record).
        if peer is not None and not (self.blockcmd and sock in self.serverside):
            self.queue_send(peer, data)

        # Record parsing: MQTT processing, filtered forwarding and local-mode ACKs.
        if sock in self.channel:
            self.parse_stream(sock, data, conf)

    def queue_send(self, sock, data):
        """Queues outbound data and tries to flush immediately."""
        pending = self.sendbuf.get(sock)
        if pending is None:
            return
        pending += data
        if len(pending) > self.max_pending:
            logger.warning("Outbound buffer overflow (peer not reading), closing connection pair")
            self.close_pair(sock)
            return
        self.sendbuf[sock] = pending
        self.flush(sock)

    def flush(self, sock):
        """Sends as much pending data as the socket accepts right now."""
        pending = self.sendbuf.get(sock)
        if not pending:
            return
        try:
            sent = sock.send(pending)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as e:
            logger.warning("Send error: %s", e)
            self.close_pair(sock)
            return
        self.sendbuf[sock] = pending[sent:]

    def parse_stream(self, sock, data, conf):
        """Reassembles complete records: filtering, local ACKs and MQTT processing."""
        buf = self.recvbuf.get(sock, b"") + data
        peer = self.channel.get(sock)
        filtering = self.blockcmd and sock in self.serverside and peer is not None
        localmode = peer is None  # No-forward mode or offline fallback: the proxy ACKs records.

        while len(buf) >= 8:
            protocol = buf[3]
            datalength = int.from_bytes(buf[4:6], "big")

            if protocol not in known_protocols or datalength == 0:
                origin = "server" if sock in self.serverside else "datalogger"
                last = self.lastrec.get(sock)
                lastinfo = f"after record type {last[0]:02x}/proto {last[1]:02x}/{last[2]}B" if last else "at stream start"
                logger.warning(
                    "Unrecognized data stream from %s (%s): %d byte(s) dropped, head: %s",
                    origin, lastinfo, len(buf), buf[:32].hex(),
                )
                if filtering:
                    self.queue_send(peer, buf)  # Fail open: an unparseable stream is never withheld.
                buf = b""
                break

            if protocol in (0x05, 0x06):
                reclength = datalength + 8
            else:
                reclength = datalength + 6

            if len(buf) < reclength:
                break  # Incomplete record: keep it buffered until more data arrives.

            record = buf[:reclength]
            buf = buf[reclength:]
            self.lastrec[sock] = (record[7], protocol, reclength)

            # Hex dump is expensive: build it only when DEBUG is active.
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Growatt record received:\n%s", format_multi_line("\t", record, 120))

            # CRC16-Modbus trailer (protocols 05/06 only).
            crc_ok = protocol not in (0x05, 0x06) or calc_crc(record[:-2]) == int.from_bytes(record[-2:], "big")
            rectype = record[7]

            if filtering:
                if crc_ok and rectype in blocked_rectypes:
                    logger.warning("Blocked remote command record (type %02x) towards datalogger", rectype)
                    continue
                self.queue_send(peer, record)
                if sock not in self.channel:
                    return  # Pair closed while queueing.

            if not crc_ok:
                logger.warning("Record CRC mismatch, record not processed")
                continue

            if localmode:
                ack = build_ack(record)
                if ack:
                    self.queue_send(sock, ack)
                    if sock not in self.channel:
                        return  # Connection closed while queueing.

            # Process only records longer than minrecl; guarded so a bad record never stops the relay.
            if len(record) > conf.minrecl:
                try:
                    procdata(conf, record)
                except Exception:
                    logger.exception("Error while processing data record, record skipped")

        if sock not in self.channel:
            return
        if len(buf) > self.max_parsebuf:
            logger.warning("Record parse buffer overflow, record parsing resynchronized")
            if filtering:
                self.queue_send(peer, buf)
            buf = b""
        if sock in self.channel:
            self.recvbuf[sock] = buf

    def close_pair(self, sock):
        """Closes a client/server connection pair (idempotent, never raises)."""
        peer = self.channel.pop(sock, None)
        if peer is not None:
            self.channel.pop(peer, None)

        for s in (sock, peer):
            if s is None:
                continue
            try:
                logger.info("%s disconnected", s.getpeername())
            except OSError:
                logger.info("Peer already disconnected")
            if s in self.input_list:
                self.input_list.remove(s)
            self.recvbuf.pop(s, None)
            self.sendbuf.pop(s, None)
            self.serverside.discard(s)
            self.fallback_deadline.pop(s, None)
            self.lastrec.pop(s, None)
            try:
                s.close()
            except OSError:
                pass

    def shutdown(self):
        """Stops the proxy and closes all sockets."""
        self.running = False
        for sock in list(self.channel):
            self.close_pair(sock)
        try:
            self.server.close()
        except OSError:
            pass
        logger.info("Grott proxy stopped")
