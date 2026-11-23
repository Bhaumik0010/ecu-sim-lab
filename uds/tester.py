import time
import can
from uds.server import UDS_REQUEST_ID, UDS_RESPONSE_ID, NRC_NAMES


class UDSTester:
    """A simple diagnostic tool that talks to the UDS server."""

    def __init__(self, channel="vcan0"):
        self.bus = can.Bus(interface="virtual", channel=channel)

    def request(self, payload, timeout=1.0):
        frame = bytes([len(payload)]) + bytes(payload)
        self.bus.send(can.Message(
            arbitration_id=UDS_REQUEST_ID,
            data=frame.ljust(8, b"\x00"),
            is_extended_id=False,
        ))
        end = time.time() + timeout
        while time.time() < end:
            msg = self.bus.recv(timeout=0.1)
            if msg and msg.arbitration_id == UDS_RESPONSE_ID:
                data = bytes(msg.data)
                return data[1:1 + data[0]]
        return None

    def shutdown(self):
        self.bus.shutdown()


def show(resp):
    """Print a response in a readable way."""
    if resp is None:
        print("   <- no response")
    elif resp[0] == 0x7F:
        print(f"   <- {resp.hex(' ')}   NEGATIVE: {NRC_NAMES.get(resp[2], 'unknown')}")
    else:
        print(f"   <- {resp.hex(' ')}   positive")