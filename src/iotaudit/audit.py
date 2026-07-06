"""Audit a kitchen-IoT device inventory against the knowledge base.

Pure functions over a device list — unit-testable, no I/O. Flags outdated/EOL firmware, default
credentials, and unencrypted management services. Complements kitchen-microsegmenter: this finds
the weak devices, that one contains the blast radius.
"""
from .knowledge import MIN_SAFE_FIRMWARE, EOL_MODELS, DEFAULT_CREDS, INSECURE_SERVICES


def _parse_version(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (ValueError, AttributeError):
        return None


def _f(rule, severity, device, message):
    return {"rule": rule, "severity": severity, "device": device, "message": message}


def audit(devices):
    findings = []
    for d in devices:
        did = d.get("id", "?")
        model = d.get("model")

        if model in EOL_MODELS:
            findings.append(_f("eol-device", "error", did,
                f"{model} is end-of-life — no security updates, replace it"))

        min_ver = MIN_SAFE_FIRMWARE.get(model)
        if min_ver is not None:
            fw = _parse_version(d.get("firmware"))
            if fw is None:
                findings.append(_f("firmware-unknown", "warn", did,
                    f'firmware "{d.get("firmware")}" is unparseable — cannot verify'))
            elif fw < min_ver:
                findings.append(_f("firmware-outdated", "error", did,
                    f'firmware {d.get("firmware")} is below the minimum safe {".".join(map(str, min_ver))}'))

        creds = d.get("credentials") or {}
        pair = (str(creds.get("username", "")).lower(), str(creds.get("password", "")))
        if pair in DEFAULT_CREDS:
            findings.append(_f("default-credentials", "error", did,
                "device uses a well-known default username/password"))
        if creds.get("password_is_default"):
            findings.append(_f("default-password-flag", "error", did,
                "password is marked as default/unchanged"))

        for svc in d.get("services", []):
            if str(svc).lower() in INSECURE_SERVICES:
                findings.append(_f("insecure-service", "warn", did,
                    f"{svc} management is unencrypted — exposes credentials/traffic"))

    return findings


def has_errors(findings):
    return any(f["severity"] == "error" for f in findings)
