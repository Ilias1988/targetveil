from __future__ import annotations

import unittest

from targetveil import Sanitizer


class SanitizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sanitizer = Sanitizer()

    def test_synthetic_canaries_do_not_leak(self) -> None:
        canaries = [
            "portal.acme-pentest.gr",
            "analyst@acme-pentest.gr",
            "10.20.30.41",
            "SyntheticPass!2026",
            "eyJhbGciOiJIUzI1NiJ9.c3ludGhldGljLXVzZXI.c3ludGhldGljLXNpZw",
        ]
        source = (
            f"POST https://{canaries[0]}/login HTTP/1.1\n"
            f"Host: {canaries[0]}\nAuthorization: Bearer {canaries[4]}\n"
            f"username={canaries[1]}&password={canaries[3]}&source={canaries[2]}"
        )
        result = self.sanitizer.sanitize(source, profile="burp")
        self.assertTrue(result.safe)
        for canary in canaries:
            self.assertNotIn(canary, result.sanitized_text)

    def test_repeated_values_share_placeholder(self) -> None:
        source = "10.0.0.8 connected to 10.0.0.8"
        result = self.sanitizer.sanitize(source, profile="nmap")
        placeholders = [item.placeholder for item in result.replacements]
        self.assertEqual(placeholders[0], placeholders[1])

    def test_custom_scope_value(self) -> None:
        result = self.sanitizer.sanitize(
            "Assessment for Acme Pentest Ltd",
            custom_values=[("CLIENT", "Acme Pentest Ltd")],
        )
        self.assertNotIn("Acme Pentest Ltd", result.sanitized_text)
        self.assertEqual(result.replacements[0].finding.detector, "custom-exact")

    def test_greek_and_eu_identifiers(self) -> None:
        source = "ΑΦΜ: 123456783\nΑΜΚΑ: 01019012345\nIBAN: GR6700000000000000000000000"
        kinds = {item.entity_type for item in self.sanitizer.scan(source, profile="strict")}
        self.assertTrue({"GREEK_AFM", "GREEK_AMKA", "IBAN"}.issubset(kinds))

    def test_file_names_are_not_domains(self) -> None:
        findings = self.sanitizer.scan("Review report.txt and request.json", profile="balanced")
        self.assertEqual(findings, [])

    def test_json_secrets_do_not_leak(self) -> None:
        canary = "NeverSendThis-JSON-Secret-991"
        source = f'{{"username":"alice@private.gr","password":"{canary}","client_secret":"also-private"}}'
        result = self.sanitizer.sanitize(source, profile="burp")
        self.assertNotIn(canary, result.sanitized_text)
        self.assertNotIn("also-private", result.sanitized_text)
        self.assertTrue(result.safe)

    def test_expanded_profiles_are_available(self) -> None:
        profiles = (
            "sqlmap", "web_discovery", "netexec", "mimikatz", "metasploit", "wireshark",
            "vuln_scanner", "cloud", "osint",
        )
        for profile in profiles:
            result = self.sanitizer.sanitize("host=portal.synthetic-client.net", profile=profile)
            self.assertIsInstance(result.sanitized_text, str)

    def test_database_credentials_do_not_leak(self) -> None:
        canaries = ("db_canary", "SqlDemoPass-881", "db.synthetic-shop.net")
        source = f"postgresql://{canaries[0]}:{canaries[1]}@{canaries[2]}:5432/customers"
        result = self.sanitizer.sanitize(source, profile="sqlmap")
        self.assertTrue(result.safe)
        for canary in canaries:
            self.assertNotIn(canary, result.sanitized_text)
        self.assertIn("DATABASE_USER", result.counts)

    def test_ad_hashes_do_not_leak(self) -> None:
        password_hash = "8846f7eaee8fb117ad06bdd830b7586c"
        source = f"Username : svc_backup\nNTLM : {password_hash}\nSYNTHETIC\\svc_backup"
        result = self.sanitizer.sanitize(source, profile="netexec")
        self.assertTrue(result.safe)
        self.assertNotIn(password_hash, result.sanitized_text)
        self.assertIn("NTLM_HASH", result.counts)

    def test_cloud_identifiers_do_not_leak(self) -> None:
        values = (
            "123456789012",
            "arn:aws:iam::123456789012:role/SyntheticAuditRole",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "private-prod-77881",
        )
        source = (
            f"AWS account ID: {values[0]}\nrole={values[1]}\n"
            f"tenant_id={values[2]}\nproject_id={values[3]}"
        )
        result = self.sanitizer.sanitize(source, profile="cloud")
        self.assertTrue(result.safe)
        for value in values:
            self.assertNotIn(value, result.sanitized_text)

    def test_verification_preserves_adjacent_log_field_boundaries(self) -> None:
        source = "host=portal.synthetic-client.net user=analyst@synthetic-client.net"
        result = self.sanitizer.sanitize(source, profile="siem")
        self.assertTrue(result.safe)


if __name__ == "__main__":
    unittest.main()
