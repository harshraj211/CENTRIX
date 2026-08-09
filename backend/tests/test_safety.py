import asyncio
import unittest

from scanner.safety import TargetSafetyError, ensure_public_target, normalise_target, url_in_scope


class SafetyTests(unittest.TestCase):
    def test_normalises_http_target(self):
        self.assertEqual(normalise_target("https://example.com/path"), "https://example.com/path")

    def test_rejects_non_http_target(self):
        with self.assertRaises(TargetSafetyError):
            normalise_target("file:///etc/passwd")

    def test_rejects_private_target(self):
        with self.assertRaises(TargetSafetyError):
            asyncio.run(ensure_public_target("http://127.0.0.1:8000"))

    def test_scope_never_leaves_origin(self):
        target = "https://example.com"
        self.assertTrue(url_in_scope("https://example.com/api/users", target, ["https://example.com/api/*"]))
        self.assertFalse(url_in_scope("https://attacker.example/api/users", target, ["*"]))


if __name__ == "__main__":
    unittest.main()
