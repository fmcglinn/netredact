"""netredact -- strip secrets and identifying data from network configurations.

Supports Cisco IOS / IOS-XE / NX-OS, Arista EOS and Juniper JunOS (both the
curly-brace and ``set`` formats).

Configuration selects a **part of the config** and chooses an **action** for
it:

  ``keep``    left exactly as it was.

  ``pseudo``  replaced by a stable, type-valid substitute derived from an HMAC
              of the original, so the config stays internally consistent and
              still loads onto a device.

  ``hash``    replaced by a stable opaque marker such as ``<DESC-f11e24>``.
              Equal values still collapse to equal markers, and the output
              announces that it was sanitised.

  ``redact``  the equality relation is destroyed -- not even "these two values
              were the same" survives. Rendered per family: ``<REMOVED>`` for
              a secret, an RFC-reserved constant for an address, since
              ``<REMOVED>`` where an IP belongs stops the config parsing.

By default only the ``secrets`` family acts, and it redacts. Everything else
is kept until you ask for it. ``pseudo`` is rejected on ``secrets``: the
substitute would be an HMAC of the real credential, and a lab config that
reached production would carry something computable.

The reasoning behind the model is in ``docs/design/actions-model.md``.

Library use::

    from netredact import Config, sanitise_text

    cfg = Config.load()                 # searches the standard locations
    result = sanitise_text(text, cfg)
    print(result.text)
    for finding in result.findings:
        print(finding)

Everything tunable lives in the configuration file; see ``Config`` and
``netredact --print-config``.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .addresses import V4_CLASS_NAMES, V6_CLASS_NAMES, classify_v4, classify_v6
from .config import (
    ACTIONS,
    ALLOWED,
    FAMILIES,
    Config,
    ConfigError,
    CustomRule,
    IPv4Policy,
    IPv6Policy,
    MacPolicy,
    PolicyConfig,
    VerifyConfig,
    find_config,
)
from .pseudonymise import PoolExhausted, Pseudonymiser
from .rules import REMOVED, build_rules, family_of, rule_names
from .sanitise import Result, Sanitiser, sanitise_text
from .vendors import detect_vendor
from .verify import Finding, check_names, verify

__all__ = [
    "__version__",
    "Config", "ConfigError", "CustomRule",
    "PolicyConfig", "IPv4Policy", "IPv6Policy", "MacPolicy", "VerifyConfig",
    "ACTIONS", "FAMILIES", "ALLOWED",
    "classify_v4", "classify_v6", "V4_CLASS_NAMES", "V6_CLASS_NAMES",
    "find_config",
    "sanitise_text", "Sanitiser", "Result",
    "Pseudonymiser", "PoolExhausted", "detect_vendor",
    "verify", "Finding", "check_names",
    "build_rules", "rule_names", "family_of", "REMOVED",
]
