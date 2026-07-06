"""Reference data for the kitchen-IoT firmware audit.

Small and honest — a real deployment feeds this from a maintained advisory feed. Kept as plain
data so the audit logic stays pure and testable.
"""

# model -> minimum safe firmware version (tuple of ints)
MIN_SAFE_FIRMWARE = {
    "acme-tempprobe": (2, 4, 0),
    "acme-kds": (3, 1, 0),
    "generic-oven": (1, 2, 0),
}

# models past end-of-life — no more security updates, replace them
EOL_MODELS = {"acme-tempprobe-v1", "oldco-sensor"}

# well-known default credential pairs (username lowercased, password as-is)
DEFAULT_CREDS = {
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("user", "user"),
}

# management protocols that expose credentials/traffic in the clear
INSECURE_SERVICES = {"telnet", "ftp", "http"}
