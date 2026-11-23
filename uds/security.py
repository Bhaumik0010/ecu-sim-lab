# Shared secret between tester and ECU.
# WEAKNESS (on purpose): key = seed XOR secret. We break this in Step 5.
SECRET = 0xA5C3


def compute_key(seed):
    return (seed ^ SECRET) & 0xFFFF