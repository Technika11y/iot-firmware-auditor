"""iot-firmware-auditor <devices.json> — audit a kitchen-IoT inventory.

Exit 1 if any error-severity finding (EOL, outdated firmware, default creds)."""
import argparse
import json
import sys

from .audit import audit, has_errors

_ORDER = {"error": 0, "warn": 1, "info": 2}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="iot-firmware-auditor")
    parser.add_argument("devices", help="device inventory JSON (list of devices)")
    args = parser.parse_args(argv)

    with open(args.devices) as fh:
        devices = json.load(fh)

    findings = audit(devices)
    for f in sorted(findings, key=lambda x: _ORDER.get(x["severity"], 9)):
        print(f"{f['severity'].upper():5} {f['rule']:22} {f['device']}: {f['message']}", file=sys.stderr)
    if not findings:
        print("OK — no firmware/credential issues found", file=sys.stderr)

    return 1 if has_errors(findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
