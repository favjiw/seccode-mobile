"""Unit tests for SecCode Mobile static rules."""

import unittest
from seccode.rules import FLUTTER_RULES, check_vibe_coding_anomalies
from seccode.models import OWASPCategory


class TestRules(unittest.TestCase):
    def test_jwt_secret_rule(self):
        code = "var dataToken = jwt.sign(SecretKey('snailly'));"
        rule = next(r for r in FLUTTER_RULES if r.rule_id == "M1_JWT_SECRET_HARDCODED")
        matches = rule.scan_file("lib/controller.dart", code)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["category"], OWASPCategory.M1)
        self.assertEqual(matches[0]["line_start"], 1)

    def test_cleartext_traffic_rule(self):
        xml = '<application android:usesCleartextTraffic="true" android:label="App">'
        rule = next(r for r in FLUTTER_RULES if r.rule_id == "M5_CLEARTEXT_TRAFFIC")
        matches = rule.scan_file("android/app/src/main/AndroidManifest.xml", xml)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["category"], OWASPCategory.M5)

    def test_mqtt_rule(self):
        code = "_client = MqttServerClient('broker.emqx.io', 'flutter_client');"
        rule = next(r for r in FLUTTER_RULES if r.rule_id == "M5_UNAUTHENTICATED_MQTT")
        matches = rule.scan_file("lib/service.dart", code)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["category"], OWASPCategory.M5)

    def test_vibe_coding_unused_secure_storage(self):
        files = {
            "pubspec.yaml": "dependencies:\n  flutter_secure_storage: ^8.0.0\n  get: 4.6.6",
            "lib/main.dart": "import 'package:flutter/material.dart';\nvoid main() {}",
        }
        anomalies = check_vibe_coding_anomalies(".", files)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["rule_id"], "M9_UNUSED_SECURE_STORAGE_ANOMALY")


if __name__ == "__main__":
    unittest.main()
