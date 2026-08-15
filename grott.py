"""Grott Growatt monitor: configuration and service entry point."""

import configparser
import logging
import os
import socket
import sys

from grottdata import shutdown_mqtt
from grottproxy import Proxy

# Logging configuration; DEBUGV is a custom level below DEBUG.
LOGGERFORMAT = "%(asctime)s - %(name)s - \t%(levelname)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGERFORMAT)
DEBUG_LEVELV_NUM = 5


def addLoggingLevel(levelName, levelNum, methodName=None):
    """Adds a custom level to the ``logging`` module and logger class.

    Args:
        levelName: Name of the new level (e.g. ``"DEBUGV"``).
        levelNum: Numeric value of the new level.
        methodName: Convenience method name; defaults to ``levelName.lower()``.

    Raises:
        AttributeError: If the level or method name is already defined.
    """
    if not methodName:
        methodName = levelName.lower()

    if hasattr(logging, levelName):
        raise AttributeError(f"{levelName} already defined in logging module")
    if hasattr(logging, methodName):
        raise AttributeError(f"{methodName} already defined in logging module")
    if hasattr(logging.getLoggerClass(), methodName):
        raise AttributeError(f"{methodName} already defined in logger class")

    def logForLevel(self, message, *args, **kwargs):
        if self.isEnabledFor(levelNum):
            self._log(levelNum, message, args, **kwargs)  # pylint: disable=protected-access

    def logToRoot(message, *args, **kwargs):
        logging.log(levelNum, message, *args, **kwargs)  # noqa: LOG015  (root-level helper is the point)

    logging.addLevelName(levelNum, levelName)
    setattr(logging, levelName, levelNum)
    setattr(logging.getLoggerClass(), methodName, logForLevel)
    setattr(logging, methodName, logToRoot)


addLoggingLevel("DEBUGV", logging.DEBUG - 5)

logger = logging.getLogger(__name__)


def detect_local_ip():
    """Returns the IPv4 address of the primary outbound interface.

    Used as the default listen address so the proxy binds to one dedicated
    interface instead of every interface. The UDP socket sends no packets, it
    only asks the kernel which local address would be used for a route.

    Returns:
        The local IPv4 address, or ``"127.0.0.1"`` when it cannot be determined.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # RFC 5737 TEST-NET-1, never contacted.
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()

logger.info("grott-minx started")


class GrottConf:
    """Runtime configuration: defaults, ``grott.ini`` overrides and record layouts."""

    def __init__(self):
        """Loads defaults, applies ``grott.ini`` overrides and builds the layouts."""
        self.loglevel = "INFO"
        self.grottport = 5279
        self.grottip = detect_local_ip()
        # Hostname preferred over a fixed IP: Growatt has moved servers in the past.
        self.growattip = "server.growatt.com"
        self.growattport = 5279
        self.mqttip = "localhost"
        self.mqttport = 1883
        self.mqtttopic = "energy/growatt"
        self.mqttuser = "grott"
        self.mqttpsw = "grott"
        self.mqttretain = False
        self.nomqtt = False
        self.inverterid = "grott"
        self.blockcmd = False
        self.noforward = False
        self.fallback = True
        self.fallbackretry = 300
        self.timesync = False

        self.minrecl = 100
        self.mindatarec = 12
        self.datarec = ["04", "50"]
        self.smartmeterrec = ["1b", "20", "1e"]
        self.includeall = True
        self.gtime = "server"
        self.sendbuf = False

        # Proxy tuning ([Proxy] section).
        self.buffersize = 4096
        self.selecttimeout = 1.0
        self.connecttimeout = 10.0
        self.maxpending = 1048576
        self.maxparsebuf = 1048576
        self.backlog = 200
        self.tcpkeepidle = 60
        self.tcpkeepintvl = 10
        self.tcpkeepcnt = 3

        # MQTT tuning ([MQTT] section).
        self.mqttkeepalive = 60
        self.mqttpublishtimeout = 2.0
        self.mqttreconnectmin = 1
        self.mqttreconnectmax = 30

        if os.path.exists("grott.ini"):
            config = configparser.ConfigParser()
            config.read("grott.ini")

            if config.has_section("Generic"):
                self.loglevel = config.get("Generic", "loglevel", fallback=self.loglevel)
                self.grottport = config.getint("Generic", "grottport", fallback=self.grottport)
                self.grottip = config.get("Generic", "grottip", fallback=self.grottip)
                self.minrecl = config.getint("Generic", "minrecl", fallback=self.minrecl)
                self.includeall = config.getboolean("Generic", "includeall", fallback=self.includeall)
                self.gtime = config.get("Generic", "time", fallback=self.gtime)
                self.sendbuf = config.getboolean("Generic", "sendbuf", fallback=self.sendbuf)
                self.blockcmd = config.getboolean("Generic", "blockcmd", fallback=self.blockcmd)

            if config.has_section("Growatt"):
                self.growattip = config.get("Growatt", "ip", fallback=self.growattip)
                self.growattport = config.getint("Growatt", "port", fallback=self.growattport)
                self.noforward = config.getboolean("Growatt", "noforward", fallback=self.noforward)
                self.fallback = config.getboolean("Growatt", "fallback", fallback=self.fallback)
                self.fallbackretry = config.getint("Growatt", "fallbackretry", fallback=self.fallbackretry)
                self.timesync = config.getboolean("Growatt", "timesync", fallback=self.timesync)

            if config.has_section("Proxy"):
                self.buffersize = config.getint("Proxy", "buffersize", fallback=self.buffersize)
                self.selecttimeout = config.getfloat("Proxy", "selecttimeout", fallback=self.selecttimeout)
                self.connecttimeout = config.getfloat("Proxy", "connecttimeout", fallback=self.connecttimeout)
                self.maxpending = config.getint("Proxy", "maxpending", fallback=self.maxpending)
                self.maxparsebuf = config.getint("Proxy", "maxparsebuf", fallback=self.maxparsebuf)
                self.backlog = config.getint("Proxy", "backlog", fallback=self.backlog)
                self.tcpkeepidle = config.getint("Proxy", "tcpkeepidle", fallback=self.tcpkeepidle)
                self.tcpkeepintvl = config.getint("Proxy", "tcpkeepintvl", fallback=self.tcpkeepintvl)
                self.tcpkeepcnt = config.getint("Proxy", "tcpkeepcnt", fallback=self.tcpkeepcnt)

            if config.has_section("MQTT"):
                self.mqttip = config.get("MQTT", "ip", fallback=self.mqttip)
                self.mqttport = config.getint("MQTT", "port", fallback=self.mqttport)
                self.mqtttopic = config.get("MQTT", "topic", fallback=self.mqtttopic)
                self.mqttuser = config.get("MQTT", "user", fallback=self.mqttuser)
                self.mqttpsw = config.get("MQTT", "password", fallback=self.mqttpsw)
                self.nomqtt = config.getboolean("MQTT", "nomqtt", fallback=self.nomqtt)
                self.mqttretain = config.getboolean("MQTT", "retain", fallback=self.mqttretain)
                self.mqttkeepalive = config.getint("MQTT", "keepalive", fallback=self.mqttkeepalive)
                self.mqttpublishtimeout = config.getfloat("MQTT", "publishtimeout", fallback=self.mqttpublishtimeout)
                self.mqttreconnectmin = config.getint("MQTT", "reconnectmindelay", fallback=self.mqttreconnectmin)
                self.mqttreconnectmax = config.getint("MQTT", "reconnectmaxdelay", fallback=self.mqttreconnectmax)

        self.set_reclayouts()

    def set_reclayouts(self):
        """Defines the record layouts: field name, hex offset, type and scale factor."""
        self.recorddict = {}
        # Layouts taken from johanmeijer/grott (grottconf.py); add layouts for other models here.
        self.recorddict1 = {
            "T06NNNNXMIN": {
                "decrypt": {"value": "true"},
                "pvserial": {"value": 76, "length": 10, "type": "text", "divide": 10},
                "date": {"value": 136, "divide": 10},
                "group1start": {"value": 150, "length": 2, "type": "num", "incl": "no"},
                "group1end": {"value": 154, "length": 2, "type": "num", "incl": "no"},
                "pvstatus": {"value": 158, "length": 2, "type": "num", "divide": 1},
                "pvpowerin": {"value": 162, "length": 4, "type": "num", "divide": 10},
                "pv1voltage": {"value": 170, "length": 2, "type": "num", "divide": 10},
                "pv1current": {"value": 174, "length": 2, "type": "num", "divide": 10},
                "pv1watt": {"value": 178, "length": 4, "type": "num", "divide": 10},
                "pv2voltage": {"value": 186, "length": 2, "type": "num", "divide": 10},
                "pv2current": {"value": 190, "length": 2, "type": "num", "divide": 10},
                "pv2watt": {"value": 194, "length": 4, "type": "num", "divide": 10},
                "pv3voltage": {"value": 202, "length": 2, "type": "num", "divide": 10},
                "pv3current": {"value": 206, "length": 2, "type": "num", "divide": 10},
                "pv3watt": {"value": 210, "length": 4, "type": "num", "divide": 10},
                "pv4voltage": {"value": 218, "length": 2, "type": "num", "divide": 10},
                "pv4current": {"value": 222, "length": 2, "type": "num", "divide": 10},
                "pv4watt": {"value": 226, "length": 4, "type": "num", "divide": 10},
                "pvpowerout": {"value": 250, "length": 4, "type": "num", "divide": 10},
                "pvfrequentie": {"value": 258, "length": 2, "type": "num", "divide": 100},
                "pvgridvoltage": {"value": 262, "length": 2, "type": "num", "divide": 10},
                "pvgridcurrent": {"value": 266, "length": 2, "type": "num", "divide": 10},
                "pvgridpower": {"value": 270, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage2": {"value": 278, "length": 2, "type": "num", "divide": 10},
                "pvgridcurrent2": {"value": 282, "length": 2, "type": "num", "divide": 10},
                "pvgridpower2": {"value": 286, "length": 4, "type": "num", "divide": 10},
                "pvgridvoltage3": {"value": 294, "length": 2, "type": "num", "divide": 10},
                "pvgridcurrent3": {"value": 298, "length": 2, "type": "num", "divide": 10},
                "pvgridpower3": {"value": 302, "length": 4, "type": "num", "divide": 10},
                "vacrs": {"value": 310, "length": 2, "type": "num", "divide": 10},
                "vacst": {"value": 314, "length": 2, "type": "num", "divide": 10},
                "vactr": {"value": 318, "length": 2, "type": "num", "divide": 10},
                "ptousertotal": {"value": 322, "length": 4, "type": "num", "divide": 10},
                "ptogridtotal": {"value": 330, "length": 4, "type": "num", "divide": 10},
                "ptoloadtotal": {"value": 338, "length": 4, "type": "num", "divide": 10},
                "totworktime": {"value": 346, "length": 4, "type": "num", "divide": 7200},
                "pvenergytoday": {"value": 354, "length": 4, "type": "num", "divide": 10},
                "pvenergytotal": {"value": 362, "length": 4, "type": "num", "divide": 10},
                "epvtotal ": {"value": 370, "length": 4, "type": "num", "divide": 10},
                "epv1today ": {"value": 378, "length": 4, "type": "num", "divide": 10},
                "epv1total": {"value": 386, "length": 4, "type": "num", "divide": 10},
                "epv2today": {"value": 394, "length": 4, "type": "num", "divide": 10},
                "epv2total": {"value": 402, "length": 4, "type": "num", "divide": 10},
                "epv3today": {"value": 410, "length": 4, "type": "num", "divide": 10},
                "epv3total": {"value": 418, "length": 4, "type": "num", "divide": 10},
                "etousertoday": {"value": 426, "length": 4, "type": "num", "divide": 10},
                "etousertotal": {"value": 434, "length": 4, "type": "num", "divide": 10},
                "etogridtoday": {"value": 442, "length": 4, "type": "num", "divide": 10},
                "etogridtotal": {"value": 450, "length": 4, "type": "num", "divide": 10},
                "eloadtoday": {"value": 458, "length": 4, "type": "num", "divide": 10},
                "eloadtotal": {"value": 466, "length": 4, "type": "num", "divide": 10},
                "deratingmode": {"value": 502, "length": 2, "type": "num", "divide": 1},
                "iso": {"value": 506, "length": 2, "type": "num", "divide": 1},
                "dcir": {"value": 510, "length": 2, "type": "num", "divide": 10},
                "dcis": {"value": 514, "length": 2, "type": "num", "divide": 10},
                "dcit": {"value": 518, "length": 2, "type": "num", "divide": 10},
                "gfci": {"value": 522, "length": 4, "type": "num", "divide": 1},
                "pvtemperature": {"value": 530, "length": 2, "type": "num", "divide": 10},
                "pvipmtemperature": {"value": 534, "length": 2, "type": "num", "divide": 10},
                "temp3": {"value": 538, "length": 2, "type": "num", "divide": 10},
                "temp4": {"value": 542, "length": 2, "type": "num", "divide": 10},
                "temp5": {"value": 546, "length": 2, "type": "num", "divide": 10},
                "pbusvoltage": {"value": 550, "length": 2, "type": "num", "divide": 10},
                "nbusvoltage": {"value": 554, "length": 2, "type": "num", "divide": 10},
                "ipf": {"value": 558, "length": 2, "type": "num", "divide": 1},
                "realoppercent": {"value": 562, "length": 2, "type": "num", "divide": 1},
                "opfullwatt": {"value": 566, "length": 4, "type": "num", "divide": 10},
                "standbyflag": {"value": 574, "length": 2, "type": "num", "divide": 1},
                "faultcode": {"value": 578, "length": 2, "type": "num", "divide": 1},
                "warningcode": {"value": 582, "length": 2, "type": "num", "divide": 1},
                "systemfaultword0": {"value": 586, "length": 2, "type": "num", "divide": 1},
                "systemfaultword1": {"value": 590, "length": 2, "type": "num", "divide": 1},
                "systemfaultword2": {"value": 594, "length": 2, "type": "num", "divide": 1},
                "systemfaultword3": {"value": 598, "length": 2, "type": "num", "divide": 1},
                "systemfaultword4": {"value": 602, "length": 2, "type": "num", "divide": 1},
                "systemfaultword5": {"value": 606, "length": 2, "type": "num", "divide": 1},
                "systemfaultword6": {"value": 610, "length": 2, "type": "num", "divide": 1},
                "systemfaultword7": {"value": 614, "length": 2, "type": "num", "divide": 1},
                "invstartdelaytime": {"value": 618, "length": 2, "type": "num", "divide": 1},
                "bdconoffstate": {"value": 630, "length": 2, "type": "num", "divide": 1},
                "drycontactstate": {"value": 634, "length": 2, "type": "num", "divide": 1},
                "group2start": {"value": 658, "length": 2, "type": "num", "incl": "no"},
                "group2end": {"value": 662, "length": 2, "type": "num", "incl": "no"},
                "edischrtoday": {"value": 666, "length": 4, "type": "num", "divide": 10},
                "edischrtotal": {"value": 674, "length": 4, "type": "num", "divide": 10},
                "echrtoday": {"value": 682, "length": 4, "type": "num", "divide": 10},
                "echrtotal": {"value": 690, "length": 4, "type": "num", "divide": 10},
                "eacchrtoday": {"value": 698, "length": 4, "type": "num", "divide": 10},
                "eacchrtotal": {"value": 706, "length": 4, "type": "num", "divide": 10},
                "priority": {"value": 742, "length": 2, "type": "num", "divide": 1},
                "epsfac": {"value": 746, "length": 2, "type": "num", "divide": 100},
                "epsvac1": {"value": 750, "length": 2, "type": "num", "divide": 10},
                "epsiac1": {"value": 754, "length": 2, "type": "num", "divide": 10},
                "epspac1": {"value": 758, "length": 4, "type": "num", "divide": 10},
                "epsvac2": {"value": 766, "length": 2, "type": "num", "divide": 10},
                "epsiac2": {"value": 770, "length": 2, "type": "num", "divide": 10},
                "epspac2": {"value": 774, "length": 4, "type": "num", "divide": 10},
                "epsvac3": {"value": 782, "length": 2, "type": "num", "divide": 10},
                "epsiac3": {"value": 786, "length": 2, "type": "num", "divide": 10},
                "epspac3": {"value": 790, "length": 4, "type": "num", "divide": 10},
                "epspac": {"value": 798, "length": 4, "type": "num", "divide": 10},
                "loadpercent": {"value": 806, "length": 2, "type": "num", "divide": 10},
                "pf": {"value": 810, "length": 2, "type": "num", "divide": 10},
                "dcv": {"value": 814, "length": 2, "type": "num", "divide": 1},
                "bdc1_sysstatemode": {"value": 830, "length": 2, "type": "num", "divide": 1},
                "bdc1_faultcode": {"value": 834, "length": 2, "type": "num", "divide": 1},
                "bdc1_warncode": {"value": 838, "length": 2, "type": "num", "divide": 1},
                "bdc1_vbat": {"value": 842, "length": 2, "type": "num", "divide": 100},
                "bdc1_ibat": {"value": 846, "length": 2, "type": "num", "divide": 10},
                "bdc1_soc": {"value": 850, "length": 2, "type": "num", "divide": 1},
                "bdc1_vbus1": {"value": 854, "length": 2, "type": "num", "divide": 10},
                "bdc1_vbus2": {"value": 858, "length": 2, "type": "num", "divide": 10},
                "bdc1_ibb": {"value": 862, "length": 2, "type": "num", "divide": 10},
                "bdc1_illc": {"value": 866, "length": 2, "type": "num", "divide": 10},
                "bdc1_tempa": {"value": 870, "length": 2, "type": "num", "divide": 10},
                "bdc1_tempb": {"value": 874, "length": 2, "type": "num", "divide": 10},
                "bdc1_pdischr": {"value": 878, "length": 4, "type": "num", "divide": 10},
                "bdc1_pchr": {"value": 886, "length": 4, "type": "num", "divide": 10},
                "bdc1_edischrtotal": {"value": 894, "length": 4, "type": "num", "divide": 10},
                "bdc1_echrtotal": {"value": 902, "length": 4, "type": "num", "divide": 10},
                "bdc1_flag": {"value": 914, "length": 2, "type": "num", "divide": 1},
                "bdc2_sysstatemode": {"value": 922, "length": 2, "type": "num", "divide": 1},
                "bdc2_faultcode": {"value": 926, "length": 2, "type": "num", "divide": 1},
                "bdc2_warncode": {"value": 930, "length": 2, "type": "num", "divide": 1},
                "bdc2_vbat": {"value": 934, "length": 2, "type": "num", "divide": 100},
                "bdc2_ibat": {"value": 938, "length": 2, "type": "num", "divide": 10},
                "bdc2_soc": {"value": 942, "length": 2, "type": "num", "divide": 1},
                "bdc2_vbus1": {"value": 946, "length": 2, "type": "num", "divide": 10},
                "bdc2_vbus2": {"value": 950, "length": 2, "type": "num", "divide": 10},
                "bdc2_ibb": {"value": 954, "length": 2, "type": "num", "divide": 10},
                "bdc2_illc": {"value": 958, "length": 2, "type": "num", "divide": 10},
                "bdc2_tempa": {"value": 962, "length": 2, "type": "num", "divide": 10},
                "bdc2_tempb": {"value": 966, "length": 2, "type": "num", "divide": 10},
                "bdc2_pdischr": {"value": 970, "length": 4, "type": "num", "divide": 10},
                "bdc2_pchr": {"value": 978, "length": 4, "type": "num", "divide": 10},
                "bdc2_edischrtotal": {"value": 986, "length": 4, "type": "num", "divide": 10},
                "bdc2_echrtotal": {"value": 994, "length": 4, "type": "num", "divide": 10},
                "bdc2_flag": {"value": 1006, "length": 4, "type": "num", "divide": 1},
                "bms_status": {"value": 1014, "length": 2, "type": "num", "divide": 1},
                "bms_error": {"value": 1018, "length": 2, "type": "num", "divide": 1},
                "bms_warninfo": {"value": 1022, "length": 2, "type": "num", "divide": 1},
                "bms_soc": {"value": 1026, "length": 2, "type": "num", "divide": 1},
                "bms_batteryvolt": {"value": 1030, "length": 2, "type": "num", "divide": 100},
                "bms_batterycurr": {"value": 1034, "length": 2, "type": "num", "divide": 100},
                "bms_batterytemp": {"value": 1038, "length": 2, "type": "num", "divide": 10},
                "bms_maxcurr": {"value": 1042, "length": 2, "type": "num", "divide": 100},
                "bms_deltavolt": {"value": 1046, "length": 2, "type": "num", "divide": 100},
                "bms_cyclecnt": {"value": 1050, "length": 2, "type": "num", "divide": 1},
                "bms_soh": {"value": 1054, "length": 2, "type": "num", "divide": 1},
                "bms_constantvolt": {"value": 1058, "length": 2, "type": "num", "divide": 100},
                "bms_bms_info": {"value": 1062, "length": 2, "type": "num", "divide": 1},
                "bms_packinfo": {"value": 1066, "length": 2, "type": "num", "divide": 1},
                "bms_usingcap": {"value": 1070, "length": 2, "type": "num", "divide": 1},
                "bms_fw": {"value": 1074, "length": 2, "type": "num", "divide": 1},
                "bms_mcuversion": {"value": 1078, "length": 2, "type": "num", "divide": 1},
                "bms_commtype": {"value": 1082, "length": 2, "type": "num", "divide": 1},
            }
        }

        self.recorddict2 = {
            "T06NN20": {
                "decrypt": {"value": "True"},
                "datalogserial": {"value": 16, "length": 10, "type": "text", "divide": 10},
                "pvserial": {"value": 76, "length": 10, "type": "text", "divide": 10},
                "date": {"value": 136, "divide": 10},
                "voltage_l1": {"value": 160, "length": 4, "type": "num", "divide": 10},
                "voltage_l2": {"value": 168, "length": 4, "type": "num", "divide": 10, "incl": "no"},
                "voltage_l3": {"value": 176, "length": 4, "type": "num", "divide": 10, "incl": "no"},
                "Current_l1": {"value": 184, "length": 4, "type": "num", "divide": 10},
                "Current_l2": {"value": 192, "length": 4, "type": "num", "divide": 10, "incl": "no"},
                "Current_l3": {"value": 200, "length": 4, "type": "num", "divide": 10, "incl": "no"},
                "act_power_l1": {"value": 208, "length": 4, "type": "numx", "divide": 10},
                "act_power_l2": {"value": 216, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "act_power_l3": {"value": 224, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "app_power_l1": {"value": 232, "length": 4, "type": "numx", "divide": 10},
                "app_power_l2": {"value": 240, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "app_power_l3": {"value": 248, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "react_power_l1": {"value": 256, "length": 4, "type": "numx", "divide": 10},
                "react_power_l2": {"value": 264, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "react_power_l3": {"value": 272, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "powerfactor_l1": {"value": 280, "length": 4, "type": "numx", "divide": 1000},
                "powerfactor_l2": {"value": 288, "length": 4, "type": "numx", "divide": 1000, "incl": "no"},
                "powerfactor_l3": {"value": 296, "length": 4, "type": "numx", "divide": 1000, "incl": "no"},
                "pos_rev_act_power": {"value": 304, "length": 4, "type": "numx", "divide": 10},
                "pos_act_power": {"value": 304, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "rev_act_power": {"value": 304, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "app_power": {"value": 312, "length": 4, "type": "numx", "divide": 10},
                "react_power": {"value": 320, "length": 4, "type": "numx", "divide": 10},
                "powerfactor": {"value": 328, "length": 4, "type": "numx", "divide": 1000},
                "frequency": {"value": 336, "length": 4, "type": "num", "divide": 10},
                "L1-2_voltage": {"value": 344, "length": 4, "type": "num", "divide": 10},
                "L2-3_voltage": {"value": 352, "length": 4, "type": "num", "divide": 10},
                "L3-1_voltage": {"value": 360, "length": 4, "type": "num", "divide": 10},
                "pos_act_energy": {"value": 368, "length": 4, "type": "numx", "divide": 10},
                "rev_act_energy": {"value": 376, "length": 4, "type": "numx", "divide": 10},
                "pos_act_energy_kvar": {"value": 384, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "rev_act_energy_kvar": {"value": 392, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "app_energy_kvar": {"value": 400, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "act_energy_kwh": {"value": 408, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
                "react_energy_kvar": {"value": 416, "length": 4, "type": "numx", "divide": 10, "incl": "no"},
            }
        }

        self.recorddict.update(self.recorddict1)
        self.recorddict.update(self.recorddict2)

conf = GrottConf()

# Apply the configured level to the root logger so all module loggers inherit it.
logging.getLogger().setLevel(getattr(logging, conf.loglevel.upper(), logging.INFO))

proxy = None
try:
    proxy = Proxy(conf)
    proxy.main(conf)
except KeyboardInterrupt:
    logger.info("Grott stopped by user")
except Exception:
    logger.exception("Grott stopped due to an unexpected error")
    sys.exit(1)
finally:
    if proxy is not None:
        proxy.shutdown()
    shutdown_mqtt()
