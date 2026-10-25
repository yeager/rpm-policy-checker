import unittest

from rpm_policy_checker.spdx_validation import validate_spdx_expression


class SpdxValidationTests(unittest.TestCase):
    def test_accepts_complete_spdx_expressions(self):
        for expression in (
            "MIT",
            "BlueOak-1.0.0",
            "GPL-3.0-or-later WITH Classpath-exception-2.0",
            "MIT AND (Apache-2.0 OR BSD-3-Clause)",
        ):
            with self.subTest(expression=expression):
                self.assertEqual(validate_spdx_expression(expression), [])

    def test_flags_unknown_identifier(self):
        self.assertEqual(
            validate_spdx_expression("MadeUp-License"),
            [("unknown", "MadeUp-License")],
        )

    def test_flags_legacy_fedora_identifier(self):
        self.assertEqual(
            validate_spdx_expression("GPLv3+"),
            [("legacy", "GPLv3+")],
        )

    def test_flags_invalid_expression_syntax(self):
        findings = validate_spdx_expression("MIT AND")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "invalid")


if __name__ == "__main__":
    unittest.main()
