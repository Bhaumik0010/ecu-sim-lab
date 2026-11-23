import random
import struct
import time
from ecus.base_ecu import BaseECU
from uds.security import compute_key

UDS_REQUEST_ID = 0x7E0   # tester -> ECU
UDS_RESPONSE_ID = 0x7E8  # ECU -> tester

SID_SESSION = 0x10
SID_READ = 0x22
SID_SECURITY = 0x27
SID_WRITE = 0x2E

DID_SW_VERSION = 0xF189   # read-only
DID_SPEED_LIMIT = 0x0100  # writable, needs security unlock

NRC_NAMES = {
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectLength",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x7F: "serviceNotSupportedInActiveSession",
}

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 10


class UDSServer(BaseECU):
    def __init__(self, channel="vcan0"):
        super().__init__("UDS-Server", channel)
        self.session = 0x01        # 0x01 default, 0x03 extended
        self.unlocked = False
        self.seed = None
        self.failed = 0
        self.locked_until = 0
        self.speed_limit = 180     # km/h, the value we protect
        self.sw_version = b"V1.0"

    # ---------- helpers ----------
    def respond(self, payload):
        # Single-frame format: first byte = payload length
        frame = bytes([len(payload)]) + payload
        self.send(UDS_RESPONSE_ID, frame.ljust(8, b"\x00"))

    def negative(self, sid, nrc):
        self.respond(bytes([0x7F, sid, nrc]))

    # ---------- main entry ----------
    def on_message(self, msg):
        if msg.arbitration_id != UDS_REQUEST_ID:
            return
        data = bytes(msg.data)
        if not data:
            return
        length = data[0]
        if length == 0 or length > len(data) - 1:
            return  # malformed frame: ignore, never crash
        payload = data[1:1 + length]

        handlers = {
            SID_SESSION: self._session,
            SID_SECURITY: self._security,
            SID_READ: self._read,
            SID_WRITE: self._write,
        }
        handler = handlers.get(payload[0])
        if handler is None:
            self.negative(payload[0], 0x11)
        else:
            handler(payload)

    # ---------- services ----------
    def _session(self, p):
        if len(p) != 2:
            return self.negative(SID_SESSION, 0x13)
        if p[1] not in (0x01, 0x03):
            return self.negative(SID_SESSION, 0x12)
        self.session = p[1]
        self.unlocked = False   # changing session re-locks the ECU
        self.seed = None
        self.respond(bytes([0x50, p[1]]))

    def _security(self, p):
        if len(p) < 2:
            return self.negative(SID_SECURITY, 0x13)
        if self.session != 0x03:
            return self.negative(SID_SECURITY, 0x7F)
        if time.time() < self.locked_until:
            return self.negative(SID_SECURITY, 0x37)

        sub = p[1]
        if sub == 0x01:                      # request seed
            if len(p) != 2:
                return self.negative(SID_SECURITY, 0x13)
            self.seed = random.randint(1, 0xFFFF)
            self.respond(bytes([0x67, 0x01]) + struct.pack(">H", self.seed))

        elif sub == 0x02:                    # send key
            if len(p) != 4:
                return self.negative(SID_SECURITY, 0x13)
            if self.seed is None:
                return self.negative(SID_SECURITY, 0x24)
            (key,) = struct.unpack(">H", p[2:4])
            expected = compute_key(self.seed)
            self.seed = None                 # a seed can be used only once
            if key == expected:
                self.unlocked = True
                self.failed = 0
                self.respond(bytes([0x67, 0x02]))
            else:
                self.failed += 1
                if self.failed >= MAX_ATTEMPTS:
                    self.locked_until = time.time() + LOCKOUT_SECONDS
                    self.failed = 0
                    self.negative(SID_SECURITY, 0x36)
                else:
                    self.negative(SID_SECURITY, 0x35)
        else:
            self.negative(SID_SECURITY, 0x12)

    def _read(self, p):
        if len(p) != 3:
            return self.negative(SID_READ, 0x13)
        did = (p[1] << 8) | p[2]
        head = bytes([0x62, p[1], p[2]])
        if did == DID_SW_VERSION:
            self.respond(head + self.sw_version)
        elif did == DID_SPEED_LIMIT:
            self.respond(head + struct.pack(">H", self.speed_limit))
        else:
            self.negative(SID_READ, 0x31)

    def _write(self, p):
        if len(p) != 5:
            return self.negative(SID_WRITE, 0x13)
        did = (p[1] << 8) | p[2]
        if did != DID_SPEED_LIMIT:
            return self.negative(SID_WRITE, 0x31)
        if not self.unlocked:
            return self.negative(SID_WRITE, 0x33)
        (value,) = struct.unpack(">H", p[3:5])
        if not 30 <= value <= 250:
            return self.negative(SID_WRITE, 0x31)
        self.speed_limit = value
        self.respond(bytes([0x6E, p[1], p[2]]))