"""RPM Policy Checker — Validate RPM packages against Fedora packaging guidelines."""
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gdk, Gio, GLib, Pango

import gettext
import locale
import os
import sys
import json
import datetime
import threading
import subprocess
import re
import tempfile
import shutil
from rpm_policy_checker.accessibility import AccessibilityManager

LOCALE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "po")
if not os.path.isdir(LOCALE_DIR):
    LOCALE_DIR = "/usr/share/locale"
locale.bindtextdomain("rpm-policy-checker", LOCALE_DIR)
gettext.bindtextdomain("rpm-policy-checker", LOCALE_DIR)
gettext.textdomain("rpm-policy-checker")
_ = gettext.gettext

APP_ID = "se.danielnylander.rpm-policy-checker"
SETTINGS_DIR = os.path.join(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
    "rpm-policy-checker"
)
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

# Check categories
CATEGORIES = {
    "naming": _("Package Naming"),
    "spec-quality": _("Spec File Quality"),
    "dependencies": _("Dependencies"),
    "file-placement": _("File Placement"),
    "licensing": _("Licensing (SPDX)"),
    "scriptlets": _("Scriptlets"),
    "macros": _("Macro Usage"),
    "changelog": _("Changelog Format"),
    "rpmlint": _("rpmlint Results"),
    "general": _("General"),
}

SEVERITY_ICONS = {"E": "❌", "W": "⚠️", "I": "ℹ️", "N": "📝", "P": "🔍"}
SEVERITY_NAMES = {}  # populated at runtime after gettext is ready


def _get_severity_names():
    return {
        "E": _("Error"),
        "W": _("Warning"),
        "I": _("Info"),
        "N": _("Note"),
        "P": _("Pedantic"),
    }


def _load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    return {"welcome_shown": False, "show_pedantic": True, "show_info": True, "distribution": "fedora"}


def _save_settings(s):
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)


# ── RPM checking logic ──────────────────────────────────────────────

def _run_rpmlint(path):
    """Run rpmlint on an RPM file or spec file."""
    results = []
    try:
        r = subprocess.run(
            ["rpmlint", path],
            capture_output=True, text=True, timeout=120
        )
        for line in (r.stdout + r.stderr).splitlines():
            # rpmlint output: "package: severity: tag detail"
            m = re.match(r'^(.+?):\s*(\w):\s*(\S+)\s*(.*)', line)
            if m:
                results.append({
                    "category": "rpmlint",
                    "severity": m.group(2),
                    "package": m.group(1).strip(),
                    "tag": m.group(3),
                    "detail": m.group(4),
                    "recommendation": "",
                })
            elif line.strip() and not line.startswith(('---', ' ', 'rpmlint:')):
                # Try simpler format: "tag: detail"
                m2 = re.match(r'^(\S+):\s*(.*)', line)
                if m2:
                    results.append({
                        "category": "rpmlint",
                        "severity": "W",
                        "package": "",
                        "tag": m2.group(1),
                        "detail": m2.group(2),
                        "recommendation": "",
                    })
    except FileNotFoundError:
        results.append({
            "category": "rpmlint",
            "severity": "E",
            "tag": "rpmlint-not-installed",
            "detail": _("rpmlint is not installed."),
            "package": "",
            "recommendation": _("Install with: sudo dnf install rpmlint"),
        })
    except Exception as e:
        results.append({
            "category": "rpmlint",
            "severity": "E",
            "tag": "rpmlint-error",
            "detail": str(e),
            "package": "",
            "recommendation": "",
        })
    return results


def _check_spec_file(spec_path):
    """Check a .spec file against Fedora packaging guidelines."""
    results = []
    try:
        with open(spec_path) as f:
            content = f.read()
            lines = content.splitlines()
    except Exception as e:
        results.append({
            "category": "general",
            "severity": "E",
            "tag": "spec-read-error",
            "detail": str(e),
            "package": "",
            "recommendation": "",
        })
        return results

    has_name = False
    has_version = False
    has_release = False
    has_summary = False
    has_license = False
    has_url = False
    has_source = False
    has_description = False
    has_changelog = False
    has_buildroot = False
    has_clean = False
    license_value = ""

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("name:"):
            has_name = True
            name_val = stripped.split(":", 1)[1].strip()
            # Naming check
            if name_val != name_val.lower():
                results.append({
                    "category": "naming",
                    "severity": "W",
                    "tag": "uppercase-package-name",
                    "detail": _("Package name '%s' contains uppercase letters.") % name_val,
                    "package": name_val,
                    "recommendation": _("Fedora guidelines recommend lowercase package names."),
                })
            if " " in name_val:
                results.append({
                    "category": "naming",
                    "severity": "E",
                    "tag": "space-in-package-name",
                    "detail": _("Package name contains spaces."),
                    "package": name_val,
                    "recommendation": _("Remove spaces from the package name."),
                })
        elif lower.startswith("version:"):
            has_version = True
        elif lower.startswith("release:"):
            has_release = True
            release_val = stripped.split(":", 1)[1].strip()
            if "%{?dist}" not in release_val:
                results.append({
                    "category": "spec-quality",
                    "severity": "W",
                    "tag": "missing-dist-tag",
                    "detail": _("Release field does not contain %%{?dist}."),
                    "package": "",
                    "recommendation": _("Add %%{?dist} to the Release tag for proper distribution tagging."),
                })
        elif lower.startswith("summary:"):
            has_summary = True
            summary_val = stripped.split(":", 1)[1].strip()
            if summary_val.endswith("."):
                results.append({
                    "category": "spec-quality",
                    "severity": "W",
                    "tag": "summary-ends-with-dot",
                    "detail": _("Summary should not end with a period."),
                    "package": "",
                    "recommendation": _("Remove the trailing period from the Summary."),
                })
            if len(summary_val) > 80:
                results.append({
                    "category": "spec-quality",
                    "severity": "W",
                    "tag": "summary-too-long",
                    "detail": _("Summary exceeds 80 characters."),
                    "package": "",
                    "recommendation": _("Keep the Summary concise (under 80 characters)."),
                })
        elif lower.startswith("license:"):
            has_license = True
            license_value = stripped.split(":", 1)[1].strip()
        elif lower.startswith("url:"):
            has_url = True
        elif lower.startswith("source") and ":" in lower:
            has_source = True
        elif lower.startswith("buildroot:"):
            has_buildroot = True
        elif stripped == "%description":
            has_description = True
        elif stripped == "%changelog":
            has_changelog = True
        elif stripped == "%clean":
            has_clean = True

    # Check required fields
    required = [
        ("name", has_name), ("version", has_version), ("release", has_release),
        ("summary", has_summary), ("license", has_license),
    ]
    for field, present in required:
        if not present:
            results.append({
                "category": "spec-quality",
                "severity": "E",
                "tag": f"missing-{field}",
                "detail": _("Required field '%s' is missing from spec file.") % field.capitalize(),
                "package": "",
                "recommendation": _("Add the %s tag to the spec file header.") % field.capitalize(),
            })

    if not has_url:
        results.append({
            "category": "spec-quality",
            "severity": "W",
            "tag": "missing-url",
            "detail": _("URL field is missing."),
            "package": "",
            "recommendation": _("Add a URL pointing to the project's homepage."),
        })

    if not has_source:
        results.append({
            "category": "spec-quality",
            "severity": "W",
            "tag": "missing-source",
            "detail": _("No Source tag found."),
            "package": "",
            "recommendation": _("Add a Source0 tag with the upstream tarball URL."),
        })

    if not has_description:
        results.append({
            "category": "spec-quality",
            "severity": "E",
            "tag": "missing-description",
            "detail": _("%%description section is missing."),
            "package": "",
            "recommendation": _("Add a %%description section with a detailed package description."),
        })

    if not has_changelog:
        results.append({
            "category": "changelog",
            "severity": "W",
            "tag": "missing-changelog",
            "detail": _("%%changelog section is missing."),
            "package": "",
            "recommendation": _("Add a %%changelog section with dated entries."),
        })

    # Deprecated features
    if has_buildroot:
        results.append({
            "category": "spec-quality",
            "severity": "I",
            "tag": "deprecated-buildroot",
            "detail": _("BuildRoot tag is deprecated in modern RPM."),
            "package": "",
            "recommendation": _("Remove the BuildRoot tag; RPM sets it automatically."),
        })

    if has_clean:
        results.append({
            "category": "spec-quality",
            "severity": "I",
            "tag": "deprecated-clean-section",
            "detail": _("%%clean section is deprecated in modern RPM."),
            "package": "",
            "recommendation": _("Remove the %%clean section; rpmbuild handles cleanup automatically."),
        })

    # License check (SPDX)
    if license_value:
        spdx_identifiers = {
            "MIT", "Apache-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
            "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1-only",
            "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
            "BSD-2-Clause", "BSD-3-Clause", "MPL-2.0", "ISC", "Zlib",
            "Unlicense", "CC0-1.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
            "Artistic-2.0", "BSL-1.0", "CC-BY-4.0", "CC-BY-SA-4.0",
            "EPL-2.0", "EUPL-1.2", "WTFPL", "0BSD",
        }
        old_fedora_licenses = {
            "GPLv2", "GPLv2+", "GPLv3", "GPLv3+", "LGPLv2", "LGPLv2+",
            "LGPLv3", "LGPLv3+", "ASL 2.0", "BSD", "MIT",
        }
        # Check each license in expression (handle AND/OR)
        license_parts = re.split(r'\s+(?:AND|OR|and|or)\s+', license_value)
        for part in license_parts:
            part = part.strip().strip("()")
            if part in old_fedora_licenses and part not in spdx_identifiers:
                results.append({
                    "category": "licensing",
                    "severity": "W",
                    "tag": "old-license-identifier",
                    "detail": _("License '%s' uses old Fedora format, not SPDX.") % part,
                    "package": "",
                    "recommendation": _("Fedora 40+ requires SPDX license identifiers. Convert to SPDX format."),
                })
            elif part not in spdx_identifiers and part not in old_fedora_licenses:
                results.append({
                    "category": "licensing",
                    "severity": "I",
                    "tag": "unknown-license-identifier",
                    "detail": _("License identifier '%s' is not a recognized SPDX identifier.") % part,
                    "package": "",
                    "recommendation": _("Check https://spdx.org/licenses/ for valid SPDX identifiers."),
                })

    # Check for common macro issues
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Hardcoded paths instead of macros
        if "/usr/lib/" in stripped and "%{_libdir}" not in stripped and not stripped.startswith("#"):
            results.append({
                "category": "macros",
                "severity": "W",
                "tag": "hardcoded-library-path",
                "detail": _("Line %d: Hardcoded /usr/lib/ instead of %%{_libdir}.") % i,
                "package": "",
                "recommendation": _("Use %%{_libdir} macro instead of hardcoded library path."),
            })
        if "/usr/bin/" in stripped and "%{_bindir}" not in stripped and not stripped.startswith("#") and not stripped.startswith("Source"):
            results.append({
                "category": "macros",
                "severity": "W",
                "tag": "hardcoded-bindir",
                "detail": _("Line %d: Hardcoded /usr/bin/ instead of %%{_bindir}.") % i,
                "package": "",
                "recommendation": _("Use %%{_bindir} macro instead of hardcoded path."),
            })
        if "/usr/share/" in stripped and "%{_datadir}" not in stripped and not stripped.startswith("#") and not stripped.startswith("Source"):
            results.append({
                "category": "macros",
                "severity": "I",
                "tag": "hardcoded-datadir",
                "detail": _("Line %d: Hardcoded /usr/share/ instead of %%{_datadir}.") % i,
                "package": "",
                "recommendation": _("Use %%{_datadir} macro for portability."),
            })
        if "/etc/" in stripped and "%{_sysconfdir}" not in stripped and not stripped.startswith("#"):
            results.append({
                "category": "macros",
                "severity": "I",
                "tag": "hardcoded-sysconfdir",
                "detail": _("Line %d: Hardcoded /etc/ instead of %%{_sysconfdir}.") % i,
                "package": "",
                "recommendation": _("Use %%{_sysconfdir} macro for portability."),
            })

    # Check scriptlets for common issues
    in_scriptlet = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped in ("%pre", "%post", "%preun", "%postun", "%pretrans", "%posttrans"):
            in_scriptlet = True
            continue
        if stripped.startswith("%") and not stripped.startswith("%{"):
            in_scriptlet = False
        if in_scriptlet:
            if "rm -rf /" in stripped or "rm -rf $RPM_BUILD_ROOT" in stripped:
                results.append({
                    "category": "scriptlets",
                    "severity": "E",
                    "tag": "dangerous-rm-in-scriptlet",
                    "detail": _("Line %d: Dangerous rm -rf in scriptlet.") % i,
                    "package": "",
                    "recommendation": _("Avoid destructive rm commands in scriptlets."),
                })
            if stripped.startswith("exit"):
                results.append({
                    "category": "scriptlets",
                    "severity": "W",
                    "tag": "exit-in-scriptlet",
                    "detail": _("Line %d: 'exit' in scriptlet may cause transaction failure.") % i,
                    "package": "",
                    "recommendation": _("Use 'exit 0' or remove exit calls; scriptlet failures can block RPM transactions."),
                })

    # Changelog format check
    in_changelog = False
    for i, line in enumerate(lines, 1):
        if line.strip() == "%changelog":
            in_changelog = True
            continue
        if in_changelog:
            if line.startswith("*"):
                # Expected: * Day Mon DD YYYY Name <email> - version
                m = re.match(r'^\*\s+\w+\s+\w+\s+\d+\s+\d{4}\s+.+\s+<.+@.+>', line)
                if not m:
                    results.append({
                        "category": "changelog",
                        "severity": "W",
                        "tag": "malformed-changelog-entry",
                        "detail": _("Line %d: Changelog entry does not follow standard format.") % i,
                        "package": "",
                        "recommendation": _("Use format: * Day Mon DD YYYY Name <email> - version-release"),
                    })

    return results


def _check_rpm_file(rpm_path):
    """Check an RPM binary file."""
    results = []
    try:
        # Extract info
        r = subprocess.run(
            ["rpm", "-qpi", rpm_path],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            results.append({
                "category": "general",
                "severity": "E",
                "tag": "rpm-query-failed",
                "detail": r.stderr.strip() or _("Failed to query RPM package."),
                "package": "",
                "recommendation": _("Ensure the file is a valid RPM package."),
            })
            return results

        info = r.stdout
        # Check for missing URL
        for line in info.splitlines():
            if line.startswith("URL"):
                url_val = line.split(":", 1)[1].strip() if ":" in line else ""
                if not url_val or url_val == "(none)":
                    results.append({
                        "category": "spec-quality",
                        "severity": "W",
                        "tag": "missing-url-in-rpm",
                        "detail": _("RPM package has no URL set."),
                        "package": "",
                        "recommendation": _("Add a URL tag to the spec file."),
                    })

        # Check file list
        r2 = subprocess.run(
            ["rpm", "-qpl", rpm_path],
            capture_output=True, text=True, timeout=30
        )
        if r2.returncode == 0:
            files = r2.stdout.splitlines()
            for fp in files:
                if fp.startswith("/usr/local/"):
                    results.append({
                        "category": "file-placement",
                        "severity": "E",
                        "tag": "file-in-usr-local",
                        "detail": _("File installed in /usr/local/: %s") % fp,
                        "package": "",
                        "recommendation": _("RPM packages must not install files under /usr/local/."),
                    })
                if fp == "/usr/lib/.build-id" or "/.build-id/" in fp:
                    continue  # Normal
                if fp.startswith("/tmp/") or fp.startswith("/var/tmp/"):
                    results.append({
                        "category": "file-placement",
                        "severity": "E",
                        "tag": "file-in-tmp",
                        "detail": _("File installed in temporary directory: %s") % fp,
                        "package": "",
                        "recommendation": _("Do not install files under /tmp/ or /var/tmp/."),
                    })

        # Check dependencies
        r3 = subprocess.run(
            ["rpm", "-qpR", rpm_path],
            capture_output=True, text=True, timeout=30
        )
        if r3.returncode == 0:
            deps = r3.stdout.splitlines()
            for dep in deps:
                dep = dep.strip()
                if dep.startswith("/") and not dep.startswith("/usr/"):
                    if dep not in ("/bin/sh", "/bin/bash", "/sbin/ldconfig"):
                        results.append({
                            "category": "dependencies",
                            "severity": "I",
                            "tag": "file-dependency",
                            "detail": _("File-based dependency: %s") % dep,
                            "package": "",
                            "recommendation": _("Consider using package-based dependencies instead of file paths where possible."),
                        })

    except FileNotFoundError:
        results.append({
            "category": "general",
            "severity": "E",
            "tag": "rpm-not-installed",
            "detail": _("rpm command not found."),
            "package": "",
            "recommendation": _("Install the rpm package to analyze RPM files."),
        })
    except Exception as e:
        results.append({
            "category": "general",
            "severity": "E",
            "tag": "rpm-error",
            "detail": str(e),
            "package": "",
            "recommendation": "",
        })

    return results


def check_package(path, run_rpmlint=True):
    """Run all checks on a package or spec file."""
    results = []

    if path.endswith(".spec"):
        results.extend(_check_spec_file(path))
        if run_rpmlint:
            results.extend(_run_rpmlint(path))
    elif path.endswith(".rpm"):
        results.extend(_check_rpm_file(path))
        if run_rpmlint:
            results.extend(_run_rpmlint(path))
    else:
        # Try as spec file if it looks like text
        try:
            with open(path) as f:
                first_line = f.readline()
            if "Name:" in first_line or "%" in first_line:
                results.extend(_check_spec_file(path))
            else:
                results.append({
                    "category": "general",
                    "severity": "E",
                    "tag": "unknown-file-type",
                    "detail": _("File is not a .rpm or .spec file."),
                    "package": "",
                    "recommendation": _("Open a .rpm package or .spec file."),
                })
        except Exception:
            results.append({
                "category": "general",
                "severity": "E",
                "tag": "unknown-file-type",
                "detail": _("File is not a .rpm or .spec file."),
                "package": "",
                "recommendation": _("Open a .rpm package or .spec file."),
            })

    return results


# ── GTK4/Adwaita UI ─────────────────────────────────────────────────

class RPMPolicyCheckerWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(
            application=app,
            title=_("RPM Policy Checker"),
            default_width=1000,
            default_height=700,
        )
        self.settings = _load_settings()
        self._results = []
        self._accessibility = AccessibilityManager(self, app)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Header
        headerbar = Adw.HeaderBar()
        title_widget = Adw.WindowTitle(
            title=_("RPM Policy Checker"),
            subtitle="",
        )
        headerbar.set_title_widget(title_widget)
        self._title_widget = title_widget

        open_btn = Gtk.Button(
            icon_name="document-open-symbolic",
            tooltip_text=_("Open .rpm or .spec file"),
        )
        open_btn.connect("clicked", self._on_open)
        headerbar.pack_start(open_btn)

        # Menu
        menu = Gio.Menu()
        menu.append(_("Settings"), "app.settings")
        menu.append(_("Copy Debug Info"), "app.copy-debug")
        menu.append(_("Keyboard Shortcuts"), "app.shortcuts")
        menu.append(_("About RPM Policy Checker"), "app.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)
        headerbar.pack_end(menu_btn)

        main_box.append(headerbar)

        # Empty state
        self._empty = Adw.StatusPage()
        self._empty.set_icon_name("package-x-generic-symbolic")
        self._empty.set_title(_("No package checked"))
        self._empty.set_description(
            _("Open or drag and drop a .rpm or .spec file to check policy compliance.")
        )
        self._empty.set_vexpand(True)

        # Success state
        self._success = Adw.StatusPage()
        self._success.set_icon_name("emblem-ok-symbolic")
        self._success.set_title(_("All checks passed!"))
        self._success.set_description(
            _("No policy issues were found. The package looks good! 👍")
        )
        self._success.set_vexpand(True)

        # Spinner state
        self._spinner_page = Adw.StatusPage()
        self._spinner_page.set_title(_("Checking package…"))
        self._spinner_page.set_description(_("Running policy checks, please wait."))
        spinner = Gtk.Spinner(spinning=True)
        spinner.set_size_request(48, 48)
        spinner.set_halign(Gtk.Align.CENTER)
        self._spinner_page.set_child(spinner)
        self._spinner_page.set_vexpand(True)

        # Results view
        scroll = Gtk.ScrolledWindow(vexpand=True)
        self._results_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._results_box.set_margin_start(12)
        self._results_box.set_margin_end(12)
        self._results_box.set_margin_top(8)
        self._results_box.set_margin_bottom(8)
        scroll.set_child(self._results_box)

        self._stack = Gtk.Stack()
        self._stack.add_named(self._empty, "empty")
        self._stack.add_named(self._success, "success")
        self._stack.add_named(self._spinner_page, "spinner")
        self._stack.add_named(scroll, "results")
        self._stack.set_vexpand(True)
        main_box.append(self._stack)

        # Status bar
        self._status = Gtk.Label(label=_("Ready"), xalign=0)
        self._status.set_margin_start(12)
        self._status.set_margin_end(12)
        self._status.set_margin_top(4)
        self._status.set_margin_bottom(4)
        self._status.add_css_class("dim-label")
        main_box.append(self._status)

        self.set_content(main_box)

        # Drag and drop
        drop_target = Gtk.DropTarget.new(Gio.File, Gdk.DragAction.COPY)
        drop_target.connect("drop", self._on_drop)
        self.add_controller(drop_target)

        # Session restore
        _restore_session(self, "rpm-policy-checker")
        self.connect("close-request", self._on_close)

        # Fullscreen toggle
        _setup_fullscreen(self, app)

        if not self.settings.get("welcome_shown"):
            GLib.idle_add(self._show_welcome)

    def _on_close(self, *_args):
        _save_session(self, "rpm-policy-checker")
        return False

    def _show_welcome(self):
        dialog = Adw.Dialog()
        dialog.set_title(_("Welcome"))
        dialog.set_content_width(420)
        dialog.set_content_height(520)

        page = Adw.StatusPage()
        page.set_icon_name("package-x-generic-symbolic")
        page.set_title(_("Welcome to RPM Policy Checker"))
        page.set_description(_(
            "Validate RPM packages against Fedora packaging guidelines.\n\n"
            "✓ Check .rpm and .spec files\n"
            "✓ Fedora Packaging Guidelines compliance\n"
            "✓ SPDX license identifier validation\n"
            "✓ Spec file quality analysis\n"
            "✓ rpmlint integration\n"
            "✓ Fix recommendations for every issue"
        ))

        btn = Gtk.Button(label=_("Get Started"))
        btn.add_css_class("suggested-action")
        btn.add_css_class("pill")
        btn.set_halign(Gtk.Align.CENTER)
        btn.set_margin_top(12)
        btn.connect("clicked", self._on_welcome_close, dialog)
        page.set_child(btn)

        box = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        hb.set_show_title(False)
        box.add_top_bar(hb)
        box.set_content(page)
        dialog.set_child(box)
        dialog.present(self)

    def _on_welcome_close(self, btn, dialog):
        self.settings["welcome_shown"] = True
        _save_settings(self.settings)
        dialog.close()

    def _on_open(self, btn):
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Open RPM or spec file"))
        ff = Gtk.FileFilter()
        ff.set_name(_("RPM and spec files"))
        ff.add_pattern("*.rpm")
        ff.add_pattern("*.spec")
        ff.add_mime_type("application/x-rpm")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(ff)
        all_filter = Gtk.FileFilter()
        all_filter.set_name(_("All files"))
        all_filter.add_pattern("*")
        filters.append(all_filter)
        dialog.set_filters(filters)
        dialog.open(self, None, self._on_file_opened)

    def _on_file_opened(self, dialog, result):
        try:
            f = dialog.open_finish(result)
            path = f.get_path()
            self._start_check(path)
        except Exception:
            pass

    def _on_drop(self, target, value, x, y):
        if isinstance(value, Gio.File):
            path = value.get_path()
            if path:
                self._start_check(path)
                return True
        return False

    def _start_check(self, path):
        self._status.set_text(_("Checking %s…") % os.path.basename(path))
        self._title_widget.set_subtitle(os.path.basename(path))
        self._stack.set_visible_child_name("spinner")
        threading.Thread(target=self._do_check, args=(path,), daemon=True).start()

    def _do_check(self, path):
        results = check_package(path)
        GLib.idle_add(self._show_results, results)

    def _show_results(self, results):
        global SEVERITY_NAMES
        SEVERITY_NAMES = _get_severity_names()
        self._results = results

        # Filter based on settings
        if not self.settings.get("show_pedantic", True):
            results = [r for r in results if r["severity"] != "P"]
        if not self.settings.get("show_info", True):
            results = [r for r in results if r["severity"] != "I"]

        # Clear results box
        while True:
            child = self._results_box.get_first_child()
            if child is None:
                break
            self._results_box.remove(child)

        if not results:
            self._stack.set_visible_child_name("success")
            self._status.set_text(_("All checks passed!"))
            return

        # Group by category
        grouped = {}
        for r in results:
            cat = r.get("category", "general")
            grouped.setdefault(cat, []).append(r)

        errors = sum(1 for r in results if r["severity"] == "E")
        warnings = sum(1 for r in results if r["severity"] == "W")

        for cat_key, cat_results in grouped.items():
            cat_name = CATEGORIES.get(cat_key, cat_key.replace("-", " ").title())

            # Category group
            group = Adw.PreferencesGroup()
            group.set_title(cat_name)
            group.set_description(
                _("%(count)d issue(s)") % {"count": len(cat_results)}
            )

            for r in cat_results:
                icon = SEVERITY_ICONS.get(r["severity"], "❓")
                sev = SEVERITY_NAMES.get(r["severity"], r["severity"])

                row = Adw.ExpanderRow()
                row.set_title(f"{icon} {r['tag']}")
                row.set_subtitle(r.get("detail", ""))

                badge = Gtk.Label(label=sev)
                badge.add_css_class("caption")
                if r["severity"] == "E":
                    badge.add_css_class("error")
                elif r["severity"] == "W":
                    badge.add_css_class("warning")
                row.add_suffix(badge)

                # Recommendation sub-row
                if r.get("recommendation"):
                    rec_row = Adw.ActionRow()
                    rec_row.set_title(_("💡 Recommendation"))
                    rec_row.set_subtitle(r["recommendation"])
                    rec_row.set_subtitle_lines(5)
                    row.add_row(rec_row)

                group.add(row)

            self._results_box.append(group)

        self._stack.set_visible_child_name("results")
        self._status.set_text(
            _("%(total)d issues: %(errors)d errors, %(warnings)d warnings")
            % {"total": len(results), "errors": errors, "warnings": warnings}
        )


class RPMPolicyCheckerApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window = None

        for name, callback in [
            ("settings", self._on_settings),
            ("copy-debug", self._on_copy_debug),
            ("shortcuts", self._on_shortcuts),
            ("about", self._on_about),
            ("quit", self._on_quit),
        ]:
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

        self.set_accels_for_action("app.quit", ["<Ctrl>q"])
        self.set_accels_for_action("app.shortcuts", ["<Ctrl>slash"])

    def do_activate(self):
        if not self.window:
            self.window = RPMPolicyCheckerWindow(self)
        self.window.present()

    def _on_settings(self, *_args):
        if not self.window:
            return
        dialog = Adw.PreferencesDialog()
        dialog.set_title(_("Settings"))

        page = Adw.PreferencesPage()

        # rpmlint group
        group = Adw.PreferencesGroup(title=_("rpmlint"))
        row = Adw.SwitchRow(title=_("Show pedantic warnings"))
        row.set_active(self.window.settings.get("show_pedantic", True))
        row.connect("notify::active", self._on_pedantic_changed)
        group.add(row)

        row2 = Adw.SwitchRow(title=_("Show info messages"))
        row2.set_active(self.window.settings.get("show_info", True))
        row2.connect("notify::active", self._on_info_changed)
        group.add(row2)
        page.add(group)

        # Distribution group
        dist_group = Adw.PreferencesGroup(title=_("Distribution"))
        dist_row = Adw.ComboRow(title=_("Target distribution"))
        model = Gtk.StringList.new([
            "Fedora", "RHEL / CentOS Stream", "openSUSE", "Mageia",
        ])
        dist_row.set_model(model)
        dist_group.add(dist_row)
        page.add(dist_group)

        dialog.add(page)
        dialog.present(self.window)

    def _on_pedantic_changed(self, row, *_args):
        self.window.settings["show_pedantic"] = row.get_active()
        _save_settings(self.window.settings)

    def _on_info_changed(self, row, *_args):
        self.window.settings["show_info"] = row.get_active()
        _save_settings(self.window.settings)

    def _on_copy_debug(self, *_args):
        if not self.window:
            return
        from . import __version__
        info = (
            f"RPM Policy Checker {__version__}\n"
            f"Python {sys.version}\n"
            f"GTK {Gtk.MAJOR_VERSION}.{Gtk.MINOR_VERSION}\n"
            f"Adw {Adw.MAJOR_VERSION}.{Adw.MINOR_VERSION}\n"
            f"OS: {os.uname().sysname} {os.uname().release}\n"
        )
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(info)
        self.window._status.set_text(_("Debug info copied"))

    def _on_shortcuts(self, *_args):
        if self.window:
            dialog = Gtk.ShortcutsWindow(transient_for=self.window)
            section = Gtk.ShortcutsSection(visible=True)
            group = Gtk.ShortcutsGroup(title=_("General"), visible=True)
            for accel, title in [
                ("<Ctrl>q", _("Quit")),
                ("<Ctrl>slash", _("Keyboard shortcuts")),
            ]:
                group.append(
                    Gtk.ShortcutsShortcut(accelerator=accel, title=title, visible=True)
                )
            section.append(group)
            dialog.append(section)
            dialog.present()

    def _on_about(self, *_args):
        from . import __version__
        dialog = Adw.AboutDialog(
            application_name=_("RPM Policy Checker"),
            application_icon="package-x-generic-symbolic",
            version=__version__,
            developer_name="Daniel Nylander",
            website="https://github.com/yeager/rpm-policy-checker",
            license_type=Gtk.License.GPL_3_0,
            issue_url="https://github.com/yeager/rpm-policy-checker/issues",
            comments=_(
                "Validate RPM packages against Fedora packaging guidelines "
                "and RPM standards with clear reports and fix suggestions."
            ),
        )
        dialog.present(self.window)

    def _on_quit(self, *_args):
        self.quit()


def main():
    app = RPMPolicyCheckerApp()
    app.run(sys.argv)


# ── Session restore ──────────────────────────────────────────────────

def _save_session(window, app_name):
    config_dir = os.path.join(os.path.expanduser("~"), ".config", app_name)
    os.makedirs(config_dir, exist_ok=True)
    state = {
        "width": window.get_width(),
        "height": window.get_height(),
        "maximized": window.is_maximized(),
    }
    try:
        with open(os.path.join(config_dir, "session.json"), "w") as f:
            json.dump(state, f)
    except OSError:
        pass


def _restore_session(window, app_name):
    path = os.path.join(os.path.expanduser("~"), ".config", app_name, "session.json")
    try:
        with open(path) as f:
            state = json.load(f)
        window.set_default_size(state.get("width", 1000), state.get("height", 700))
        if state.get("maximized"):
            window.maximize()
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass


# ── Fullscreen toggle (F11) ─────────────────────────────────────────

def _setup_fullscreen(window, app):
    if not app.lookup_action("toggle-fullscreen"):
        action = Gio.SimpleAction.new("toggle-fullscreen", None)
        action.connect(
            "activate",
            lambda a, p: (
                window.unfullscreen() if window.is_fullscreen() else window.fullscreen()
            ),
        )
        app.add_action(action)
        app.set_accels_for_action("app.toggle-fullscreen", ["F11"])
