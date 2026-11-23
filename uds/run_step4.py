import struct
from uds.server import UDSServer
from uds.tester import UDSTester, show
from uds.security import compute_key

server = UDSServer()
server.start()
tester = UDSTester()

print("1. Read software version (open to everyone)")
show(tester.request([0x22, 0xF1, 0x89]))

print("2. Try to write the speed limit WITHOUT unlocking")
show(tester.request([0x2E, 0x01, 0x00]) + b"")
show(tester.request([0x2E, 0x01, 0x00, 0x00, 0x78]))

print("3. Ask for a seed in the default session")
show(tester.request([0x27, 0x01]))

print("4. Switch to extended session, request seed")
show(tester.request([0x10, 0x03]))
r = tester.request([0x27, 0x01])
show(r)
seed = struct.unpack(">H", r[2:4])[0]

print("5. Send a WRONG key")
show(tester.request([0x27, 0x02, 0x00, 0x00]))

print("6. Request a new seed and send the CORRECT key")
r = tester.request([0x27, 0x01])
seed = struct.unpack(">H", r[2:4])[0]
key = compute_key(seed)
show(tester.request([0x27, 0x02] + list(struct.pack(">H", key))))

print("7. Write speed limit = 120 km/h, then read it back")
show(tester.request([0x2E, 0x01, 0x00, 0x00, 0x78]))
show(tester.request([0x22, 0x01, 0x00]))

print("8. Brute-force protection: 3 wrong keys in a row")
tester.request([0x10, 0x03])  # new session re-locks the ECU
for i in range(3):
    tester.request([0x27, 0x01])
    show(tester.request([0x27, 0x02, 0x00, 0x00]))
print("   Now even a seed request is refused:")
show(tester.request([0x27, 0x01]))

server.stop()
tester.shutdown()