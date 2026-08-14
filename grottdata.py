"""Growatt record decryption, decoding and MQTT publishing."""

import codecs
import json
import logging
import textwrap
import threading
from datetime import datetime

import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


def format_multi_line(prefix, string, size=80):
    r"""Formats a bytes or string value as multiple prefixed lines (debug dumps).

    Args:
        prefix: String prepended to every line.
        string: Value to format; bytes are rendered as ``\x..`` escapes.
        size: Maximum line width, prefix included.

    Returns:
        The formatted multi-line string.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(rf'\x{byte:02x}' for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def decrypt(decdata):
    """Decrypts a Growatt record by XOR-ing its body with the "Growatt" mask.

    The first 8 bytes (header) are not encrypted and are kept as-is.

    Args:
        decdata: Raw record bytes.

    Returns:
        The full record as a lowercase hex string.
    """
    mask = b"Growatt"
    nmask = len(mask)

    header = decdata[:8]
    body = decdata[8:]

    decrypted_body = bytearray(b ^ mask[i % nmask] for i, b in enumerate(body))

    return (header + decrypted_body).hex()


class MQTTPublisher:
    """MQTT publisher that keeps a single persistent connection to the broker.

    The paho network loop runs in a background daemon thread and reconnects
    automatically with configurable exponential backoff. A broker outage never
    blocks or crashes the caller: while disconnected, publish() fails fast
    (bounded by ``timeout``) and returns False instead of hanging.
    """

    def __init__(self, hostname, port, client_id, username=None, password=None,
                 keepalive=60, reconnect_min=1, reconnect_max=30):
        """Initializes the client and its reconnect policy (does not connect yet).

        Args:
            hostname: Broker hostname or IP address.
            port: Broker TCP port.
            client_id: MQTT client identifier.
            username: Optional broker username; the password is only sent with it.
            password: Optional broker password.
            keepalive: MQTT keepalive interval in seconds.
            reconnect_min: Minimum reconnect backoff delay in seconds.
            reconnect_max: Maximum reconnect backoff delay in seconds.
        """
        self.hostname = hostname
        self.port = port
        self.client_id = client_id
        self.keepalive = keepalive
        self._connected = threading.Event()
        self._lock = threading.Lock()
        self._started = False
        self._closing = False

        try:
            # paho-mqtt >= 2.0
            self._client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
            )
        except AttributeError:
            # paho-mqtt 1.x
            self._client = mqtt.Client(client_id=client_id)

        if username:
            self._client.username_pw_set(username, password)

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.reconnect_delay_set(min_delay=reconnect_min, max_delay=reconnect_max)

    # Callback signatures are compatible with paho 1.x and 2.x (invoked positionally).
    def _on_connect(self, _client, _userdata, _flags, reason_code, _properties=None):
        failed = bool(getattr(reason_code, "is_failure", reason_code != 0))
        if failed:
            logger.warning("MQTT connection refused by %s:%s (rc=%s)", self.hostname, self.port, reason_code)
            return
        self._connected.set()
        logger.info("MQTT connected to %s:%s", self.hostname, self.port)

    def _on_disconnect(self, _client, _userdata, *_args):
        self._connected.clear()
        if self._closing:
            logger.debug("MQTT disconnected (shutdown)")
        else:
            logger.warning("MQTT connection to %s:%s lost, automatic reconnection active", self.hostname, self.port)

    def start(self):
        """Starts the background network loop (idempotent, non-blocking)."""
        with self._lock:
            if self._started:
                return
            try:
                self._client.connect_async(self.hostname, self.port, keepalive=self.keepalive)
            except Exception as e:
                # E.g. malformed host/port; resolvable errors are retried by the loop thread.
                logger.error("MQTT connect setup failed for %s:%s : %s", self.hostname, self.port, e)
            self._client.loop_start()
            self._started = True

    def publish(self, topic, payload, qos=0, retain=False, timeout=2.0):
        """Publishes a message through the persistent connection.

        Waits at most ``timeout`` seconds for a broker connection; never raises.

        Args:
            topic: MQTT topic to publish to.
            payload: Message payload.
            qos: MQTT quality of service level (0-2).
            retain: Whether the broker should retain the message.
            timeout: Maximum seconds to wait for connection and confirmation.

        Returns:
            bool: True if the message was handed over to the broker connection.
        """
        if not self._started:
            self.start()

        if not self._connected.wait(timeout):
            logger.warning(
                "MQTT broker %s:%s not connected, message for topic %s dropped", self.hostname, self.port, topic
            )
            return False

        try:
            msginfo = self._client.publish(topic, payload=payload, qos=qos, retain=retain)
        except Exception as e:
            logger.error("MQTT publish error for topic %s : %s", topic, e)
            return False

        if msginfo.rc != mqtt.MQTT_ERR_SUCCESS:
            logger.warning("MQTT publish failed for topic %s (rc=%s)", topic, msginfo.rc)
            return False

        try:
            msginfo.wait_for_publish(timeout)
        except Exception as e:
            # Confirmation unavailable; the message remains queued in the client.
            logger.debug("MQTT publish confirmation not available: %s", e)

        if qos > 0 and not msginfo.is_published():
            logger.warning("MQTT delivery not confirmed within %.1fs for topic %s", timeout, topic)
            return False

        logger.debug("MQTT message published to topic: %s", topic)
        return True

    def close(self):
        """Stops the network loop and disconnects cleanly."""
        with self._lock:
            if not self._started:
                return
            self._started = False
            self._closing = True
        try:
            self._client.disconnect()
        except Exception as e:
            logger.debug("MQTT disconnect during shutdown ignored: %s", e)
        self._client.loop_stop()
        logger.info("MQTT publisher stopped")


# Shared MQTT publisher: one persistent, auto-reconnecting connection for all records.
_mqtt_publisher = None


def _get_mqtt_publisher(conf):
    """Returns the shared MQTTPublisher, creating and starting it on first use."""
    global _mqtt_publisher
    if _mqtt_publisher is None:
        _mqtt_publisher = MQTTPublisher(
            hostname=conf.mqttip,
            port=conf.mqttport,
            client_id=conf.inverterid,
            username=conf.mqttuser,
            password=conf.mqttpsw,
            keepalive=conf.mqttkeepalive,
            reconnect_min=conf.mqttreconnectmin,
            reconnect_max=conf.mqttreconnectmax,
        )
        _mqtt_publisher.start()
    return _mqtt_publisher


def shutdown_mqtt():
    """Closes the shared MQTT publisher (program shutdown)."""
    global _mqtt_publisher
    if _mqtt_publisher is not None:
        _mqtt_publisher.close()
        _mqtt_publisher = None


def AutoCreateLayout(conf, data, protocol, recordtype):
    """Selects the record layout and returns the decoded hex payload.

    Args:
        conf: Active configuration object.
        data: Raw record bytes.
        protocol: Protocol id from the header ("00", "02", "05" or "06").
        recordtype: Record type from the header (e.g. "04", "50", "20").

    Returns:
        A ``(layout, result_string)`` tuple: layout is "T06NN20" for smart meter
        records, "T06NNNNXMIN" for inverter records or "none" for short ACK
        records; result_string is the decrypted record as a hex string.
    """
    datalen = len(data)

    # Protocols 05/06 are XOR-masked; the others are plain.
    if protocol in ("05", "06"):
        result_string = decrypt(data)
    else:
        result_string = data.hex()

    # Short records are ACKs and carry no decodable data.
    if datalen < conf.mindatarec:
        layout = "none"
        return (layout, result_string)

    if recordtype in conf.smartmeterrec:
        layout = "T06NN20"
    else:
        layout = "T06NNNNXMIN"

    return (layout, result_string)


def _format_value(key_conf, result_string):
    """Decodes a single field from the hex payload.

    Args:
        key_conf: Layout entry with ``value`` (hex offset), ``length`` and ``type``.
        result_string: Decrypted record as a hex string.

    Returns:
        The decoded value (str for ``text``, int for ``num`` and signed ``numx``),
        or None when the field cannot be decoded.
    """
    try:
        keytype = key_conf.get("type", "num")
        key_value_start = key_conf["value"]
        key_length = key_conf["length"]

        key_hex = result_string[key_value_start : key_value_start + (key_length * 2)]

        if keytype == "text":
            return codecs.decode(key_hex, "hex").decode("utf-8")
        if keytype == "num":
            return int(key_hex, 16)
        if keytype == "numx":
            keybytes = bytes.fromhex(key_hex)
            return int.from_bytes(keybytes, byteorder="big", signed=True)

    except Exception:
        return None
    return None


def _get_date(conf, result_string, layout, buffered):
    """Determines the record timestamp.

    Uses the device timestamp embedded in the record for buffered records (or
    when ``time != server``); otherwise the arrival time is used.

    Returns:
        An ISO-8601 timestamp string without timezone.
    """
    dateoffset = int(conf.recorddict[layout].get("date", {}).get("value", 0))
    jsondate = datetime.now().replace(microsecond=0).isoformat()

    if dateoffset > 0 and (conf.gtime != "server" or buffered == "yes"):
        logger.debug("\t - Grott data record date/time processing started")
        try:
            pvyear = f"20{int(result_string[dateoffset : dateoffset + 2], 16):02d}"
            pvmonth = f"{int(result_string[dateoffset + 2 : dateoffset + 4], 16):02d}"
            pvday = f"{int(result_string[dateoffset + 4 : dateoffset + 6], 16):02d}"
            pvhour = f"{int(result_string[dateoffset + 6 : dateoffset + 8], 16):02d}"
            pvminute = f"{int(result_string[dateoffset + 8 : dateoffset + 10], 16):02d}"
            pvsecond = f"{int(result_string[dateoffset + 10 : dateoffset + 12], 16):02d}"

            pvdate = f"{pvyear}-{pvmonth}-{pvday}T{pvhour}:{pvminute}:{pvsecond}"
            # Validate the date before trusting it.
            datetime.strptime(pvdate, "%Y-%m-%dT%H:%M:%S")
            jsondate = pvdate
            logger.debug("\t - date-time: %s", jsondate)
        except ValueError:
            logger.debug("\t - no or no valid time/date found, grott server time will be used")
    else:
        logger.debug("\t - Grott server date/time used")

    return jsondate


def procdata(conf, data):
    """Decodes one complete Growatt record and publishes it to MQTT.

    Args:
        conf: Active configuration object.
        data: One complete record, header included.
    """
    logger.debug("Data processing started")

    header = data[0:8].hex()
    protocol = header[6:8]  # Protocol type (00, 02, 05, 06).
    recordtype = header[14:16]  # Record type (04/50 inverter data, 20/1b smart meter).
    buffered = "yes" if recordtype == "50" else "no"  # Type 50 is a historical (buffered) record.

    layout, result_string = AutoCreateLayout(conf, data, protocol, recordtype)

    if layout == "none":
        logger.warning("No matching layout found data record will not be processed")
        return

    logger.debug("Record layout used: %s", layout)

    # Hex dumps are expensive: build them only when DEBUG is active.
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Original data:\n%s", format_multi_line("\t", data, 80))
        logger.debug("Decrypted data:\n%s", format_multi_line("\t", result_string, 80))

    if recordtype not in conf.datarec + conf.smartmeterrec:
        logger.debug("Grott data ack record or data record not defined, no processing done")
        return

    # Decoded field values, keyed by layout keyword.
    definedkey = {}

    logger.debug("\t - Growatt new layout processing")
    logger.debug("\t\t - record layout : %s", layout)

    for keyword, key_conf in conf.recorddict[layout].items():
        if keyword in ("decrypt", "date"):
            continue

        include = key_conf.get("incl", "yes") != "no"

        if include or conf.includeall:
            val = _format_value(key_conf, result_string)
            if val is not None:
                definedkey[keyword] = val
            else:
                logger.debug("\t - grottdata - keyword could not be decoded : %s", keyword)

    if "pvserial" not in definedkey:
        definedkey["pvserial"] = conf.inverterid
        logger.debug("\t - pvserial not found, using configured inverterid: %s", definedkey["pvserial"])

    jsondate = _get_date(conf, result_string, layout, buffered)

    logger.debug("\t - Grott values retrieved:")
    for key, value in definedkey.items():
        keydivide = conf.recorddict[layout].get(key, {}).get("divide", 1)
        if isinstance(value, (int, float)) and keydivide != 1:
            printkey = f"{value / keydivide:.1f}"
        else:
            printkey = value
        logger.debug("\t\t - %s : %s", key.ljust(20), printkey)

    if recordtype == "20" and not 0 <= definedkey.get("voltage_l1", 0) / 10 <= 500:
        logger.warning("\t - Grott invalid 0120 record processing stopped")
        return

    if recordtype in conf.smartmeterrec:
        deviceid = definedkey.get("datalogserial", "")
    else:
        deviceid = definedkey.get("pvserial", "")

    jsonobj = {"device": deviceid, "time": jsondate, "buffered": buffered, "values": definedkey}

    jsonmsg = json.dumps(jsonobj)

    logger.debug("\t - MQTT jsonmsg: %s", jsonmsg)

    if buffered == "yes" and not getattr(conf, "sendbuf", False):
        logger.debug("\t - Buffered record not sent: sendbuf = False")
        return

    if conf.nomqtt:
        logger.debug("\t - No MQTT message sent, MQTT disabled")
        return

    logger.debug("\t - Grott MQTT topic used : %s", conf.mqtttopic)

    if conf.mqttretain:
        logger.debug("\t - Grott MQTT message retain enabled")

    try:
        logger.debug("MQTT message about to be sent for deviceid: %s", deviceid)
        mqtt_publisher = _get_mqtt_publisher(conf)
        success = mqtt_publisher.publish(
            topic=conf.mqtttopic, payload=jsonmsg, qos=0, retain=conf.mqttretain, timeout=conf.mqttpublishtimeout
        )
        if success:
            logger.debug("MQTT message published for deviceid: %s", deviceid)
        else:
            logger.error("MQTT message publishing failed for deviceid: %s", deviceid)
    except Exception as e:
        logger.error("\t - Grott MQTT publish error: %s", e)
