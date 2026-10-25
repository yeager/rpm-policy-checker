import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def _load_checker_module():
    """Import the checker without requiring GTK libraries in test runners."""
    class Namespace:
        pass

    gtk = Namespace()
    adw = Namespace()
    adw.ApplicationWindow = type("ApplicationWindow", (), {})
    adw.Application = type("Application", (), {})
    repository = types.ModuleType("gi.repository")
    repository.Gtk = gtk
    repository.Adw = adw
    repository.Gdk = Namespace()
    repository.Gio = Namespace()
    repository.GLib = Namespace()
    repository.Pango = Namespace()
    gi = types.ModuleType("gi")
    gi.require_version = lambda *_args: None
    gi.repository = repository

    with patch.dict(sys.modules, {"gi": gi, "gi.repository": repository}):
        sys.modules.pop("rpm_policy_checker.main", None)
        return importlib.import_module("rpm_policy_checker.main")


class SpecLicenseCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checker = _load_checker_module()

    def check_license(self, expression):
        spec = (
            "Name: example\nVersion: 1\nRelease: 1%{?dist}\n"
            "Summary: Example\nLicense: " + expression + "\n"
            "URL: https://example.org\nSource0: https://example.org/source.tar.gz\n"
            "%description\nExample package\n%changelog\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example.spec"
            path.write_text(spec)
            return [
                finding["tag"]
                for finding in self.checker._check_spec_file(str(path))
                if finding["category"] == "licensing"
            ]

    def test_module_imports_without_a_locale_api_error(self):
        self.assertTrue(callable(self.checker.main))

    def test_accepts_valid_spdx_with_exception_and_parentheses(self):
        self.assertEqual(
            self.check_license("MIT AND (Apache-2.0 OR BSD-3-Clause)"), []
        )

    def test_reports_unknown_identifier(self):
        self.assertIn(
            "unknown-license-identifier", self.check_license("MadeUp-License")
        )

    def test_reports_legacy_identifier(self):
        self.assertIn("old-license-identifier", self.check_license("GPLv3+"))


if __name__ == "__main__":
    unittest.main()
