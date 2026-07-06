import unittest

from iotaudit.audit import audit, has_errors


def dev(**over):
    base = {
        "id": "d1", "model": "acme-kds", "firmware": "3.1.0",
        "credentials": {"username": "kitchen", "password": "s3cret"}, "services": ["https"],
    }
    base.update(over)
    return base


def rules(devices):
    return [f["rule"] for f in audit(devices)]


class AuditTests(unittest.TestCase):
    def test_clean_device_no_findings(self):
        self.assertEqual(audit([dev()]), [])

    def test_outdated_firmware_is_error(self):
        self.assertIn("firmware-outdated", rules([dev(firmware="3.0.5")]))
        self.assertTrue(has_errors(audit([dev(firmware="3.0.5")])))

    def test_firmware_equal_to_min_is_ok(self):
        self.assertNotIn("firmware-outdated", rules([dev(firmware="3.1.0")]))

    def test_eol_model_is_error(self):
        self.assertIn("eol-device", rules([dev(model="oldco-sensor")]))

    def test_default_credentials_error(self):
        self.assertIn("default-credentials", rules([dev(credentials={"username": "admin", "password": "admin"})]))

    def test_default_password_flag_error(self):
        creds = {"username": "x", "password": "y", "password_is_default": True}
        self.assertIn("default-password-flag", rules([dev(credentials=creds)]))

    def test_insecure_service_warns(self):
        self.assertIn("insecure-service", rules([dev(services=["telnet", "https"])]))

    def test_unparseable_firmware_warns(self):
        self.assertIn("firmware-unknown", rules([dev(firmware="latest")]))

    def test_unknown_model_skips_firmware_check(self):
        self.assertNotIn("firmware-outdated", rules([dev(model="mystery-device", firmware="0.0.1")]))


if __name__ == "__main__":
    unittest.main()
