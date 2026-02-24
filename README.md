# RPM Policy Checker

A GTK4/Adwaita application to validate RPM packages against Fedora packaging guidelines and RPM standards.

![License](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)

## Features

- **Spec file analysis** — Check naming, required fields, macro usage, scriptlets, changelog format
- **RPM binary checks** — File placement, dependencies, metadata validation
- **SPDX license validation** — Detect old Fedora license identifiers and suggest SPDX equivalents
- **rpmlint integration** — Use rpmlint as backend for comprehensive checks
- **Grouped results** — Issues organized by category (naming, dependencies, licensing, etc.)
- **Fix recommendations** — Every issue includes actionable suggestions
- **Drag and drop** — Drop .rpm or .spec files directly onto the window
- **Modern UI** — GTK4 with libadwaita for a native GNOME experience

## Installation

### From source

```bash
pip install .
rpm-policy-checker
```

### Dependencies

- Python ≥ 3.10
- GTK4 and libadwaita
- PyGObject
- rpmlint (optional, for rpmlint integration)
- rpm (for RPM binary analysis)

On Fedora:

```bash
sudo dnf install python3-gobject gtk4 libadwaita rpmlint
```

## Usage

1. Open the app
2. Click the open button or drag and drop a `.rpm` or `.spec` file
3. Review the categorized results with fix recommendations

## License

GPL-3.0-or-later

## Author

Daniel Nylander <daniel@danielnylander.se>
