"""SPDX expression validation helpers."""

import re

from license_expression import ExpressionError, get_spdx_licensing


_SPDX = get_spdx_licensing()
_LEGACY_FEDORA_IDS = {
    "GPLv2",
    "GPLv2+",
    "GPLv3",
    "GPLv3+",
    "LGPLv2",
    "LGPLv2+",
    "LGPLv3",
    "LGPLv3+",
    "ASL 2.0",
    "BSD",
}
_LEGACY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:"
    + "|".join(re.escape(item) for item in sorted(_LEGACY_FEDORA_IDS, key=len, reverse=True))
    + r")(?![A-Za-z0-9_.-])"
)


def validate_spdx_expression(expression):
    """Return ``(kind, identifier)`` findings for an SPDX license expression.

    ``kind`` is ``legacy``, ``unknown``, or ``invalid``. The SPDX list and
    grammar come from the license-expression package rather than a local,
    incomplete identifier allowlist.
    """
    findings = []
    try:
        _SPDX.parse(expression, validate=True, strict=True)
    except ExpressionError as error:
        message = str(error)
        prefix = "Unknown license key(s): "
        if message.startswith(prefix):
            for identifier in message[len(prefix):].split(", "):
                kind = "legacy" if identifier in _LEGACY_FEDORA_IDS else "unknown"
                findings.append((kind, identifier))
            return findings
        return [("invalid", expression)]

    # Older Fedora identifiers can be accepted as aliases by some SPDX
    # parsers. Preserve the Fedora-specific migration warning in that case.
    for match in _LEGACY_PATTERN.finditer(expression):
        identifier = match.group(0)
        if identifier not in {value for kind, value in findings if kind == "legacy"}:
            findings.append(("legacy", identifier))

    return findings
