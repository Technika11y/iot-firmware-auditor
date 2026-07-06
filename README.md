# Kitchen IoT Firmware Auditor

> Audits a commercial-kitchen IoT inventory for **outdated/EOL firmware, default credentials, and
> unencrypted management services** — the weak devices that a flat network lets pivot to the POS.
>
> Part of the **Technika11y** suite · *Root access for everyone.* · pairs with `kitchen-microsegmenter`

![status](https://img.shields.io/badge/status-pre--alpha-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.10%2B-informational)

---

## Status — read this first

**Pre-alpha (`v0.1.0a0`). Honest state of the code:**

| Capability | State |
|---|---|
| Flag outdated firmware (below a per-model minimum) | ✅ works, tested |
| Flag end-of-life models | ✅ works, tested |
| Flag well-known default credentials + a "password unchanged" flag | ✅ works, tested |
| Flag unencrypted management services (telnet/ftp/http) | ✅ works, tested |
| Exit 1 on any error-severity finding (CI gate) | ✅ works |
| Live device probing / discovery | ❌ out of scope — you supply the inventory |
| Advisory-feed-backed knowledge base (CVEs, real firmware floors) | ⚠️ starter data only — [roadmap](#roadmap) |

The knowledge base (safe-firmware floors, EOL models, default creds) is a **small starter set**.
Feed it from a maintained advisory source before relying on it.

## Why it exists

`kitchen-microsegmenter` contains the blast radius; this finds the devices most likely to *be* the
breach — the temp probe on ancient firmware with `admin/admin` still set. Point it at your device
inventory and it tells you which ones to patch, replace, or lock down first.

## Usage

```bash
PYTHONPATH=src python -m iotaudit.cli examples/devices.json
```

```
ERROR firmware-outdated      kds-1: firmware 3.0.5 is below the minimum safe 3.1.0
ERROR default-credentials    kds-1: device uses a well-known default username/password
WARN  insecure-service       kds-1: telnet management is unencrypted — exposes credentials/traffic
```

## Roadmap

- [ ] Advisory-feed-backed knowledge base (CVE / vendor floors)
- [ ] Credential entropy scoring (not just exact default matches)
- [ ] Emit a device-risk weighting for `kitchen-microsegmenter` to consume
- [ ] SARIF output + the shared Technika11y CI gate

## License

[Apache-2.0](LICENSE). See [`SECURITY.md`](SECURITY.md).
