import threading
import time
import can


class BaseECU:
    """Base class for every virtual ECU on the CAN bus."""

    tick_interval = 0.1  # seconds between periodic transmissions

    def __init__(self, name, channel="vcan0"):
        self.name = name
        # 'virtual' = software-only CAN bus, no hardware needed
        self.bus = can.Bus(interface="virtual", channel=channel)
        self._running = False
        self._threads = []

    def send(self, arbitration_id, data):
        """Broadcast one CAN frame to every ECU on the bus."""
        msg = can.Message(
            arbitration_id=arbitration_id,
            data=data,
            is_extended_id=False,
        )
        self.bus.send(msg)

    def on_message(self, msg):
        """Override in a subclass to react to received frames."""
        pass

    def on_tick(self):
        """Override in a subclass to send periodic frames."""
        pass

    def _rx_loop(self):
        while self._running:
            msg = self.bus.recv(timeout=0.1)
            if msg is not None:
                self.on_message(msg)

    def _tick_loop(self):
        while self._running:
            self.on_tick()
            time.sleep(self.tick_interval)

    def start(self):
        self._running = True
        for target in (self._rx_loop, self._tick_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._running = False
        for t in self._threads:
            t.join(timeout=1)
        self.bus.shutdown()