"""The shipped examples must load and work, and generated docs must be current."""

import itertools
import re
import subprocess
import sys
from pathlib import Path

import pytest

from netredact import Config, sanitise_text

from .conftest import SALT

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
EXAMPLES = sorted((DOCS / "examples").glob("*.toml"))
#: the destination profiles, i.e. everything except the generated annotated one
PROFILES = [p for p in EXAMPLES if p.name != "annotated.toml"]


def load(path: Path) -> Config:
    cfg = Config.load(path)
    cfg.salt_file = None                     # never touch the real salt in tests
    return cfg


def test_examples_exist():
    assert EXAMPLES, "no example configs found"
    names = {p.name for p in EXAMPLES}
    assert "annotated.toml" in names
    assert any(n.startswith("01-") for n in names)
    assert len(PROFILES) >= 5


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_config_loads(path):
    cfg = Config.load(path)
    assert cfg.source == str(path)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_config_sanitises_every_fixture(path, fixtures):
    cfg = load(path)
    for cfgfile in sorted(fixtures.glob("*.cfg")):
        result = sanitise_text(cfgfile.read_text(), cfg, salt=SALT)
        assert result.text
        assert result.findings == [], f"{path.name} / {cfgfile.name}: " + \
            "; ".join(str(f) for f in result.findings)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_config_is_idempotent_where_it_can_be(path, cisco):
    """Nothing an example does may change on a second pass, bar pseudo addresses.

    ``pseudo`` addresses re-map deliberately -- the default pool overlaps real
    CGNAT space -- so only the profiles that keep or destroy addressing are
    checked for byte equality; the rest are checked for a stable line count.
    """
    cfg = load(path)
    once = sanitise_text(cisco, cfg, salt=SALT).text
    twice = sanitise_text(once, cfg, salt=SALT).text
    if cfg.ipv4.any_active() or cfg.ipv6.any_active():
        assert len(twice.splitlines()) == len(once.splitlines())
    else:
        assert twice == once


def test_annotated_example_matches_print_config():
    body = (DOCS / "examples" / "annotated.toml").read_text()
    assert Config().to_toml() in body


def test_profiles_are_actually_different(cisco):
    """Guards against an example being copied and not edited."""
    outputs = {p.name: sanitise_text(cisco, load(p), salt=SALT).text
               for p in PROFILES}
    for a, b in itertools.combinations(sorted(outputs), 2):
        assert outputs[a] != outputs[b], f"{a} and {b} behave identically"


def test_the_first_profile_is_the_default(cisco):
    """01 spells out the defaults, so it must behave exactly like them."""
    spelled_out = sanitise_text(cisco, load(DOCS / "examples" /
                                            "01-secrets-only.toml"), salt=SALT)
    default = sanitise_text(cisco, Config(), salt=SALT)
    assert spelled_out.text == default.text


def test_public_publication_removes_identity(cisco):
    cfg = load(DOCS / "examples" / "05-public-publication.toml")
    out = sanitise_text(cisco, cfg, salt=SALT).text
    for leak in ("northwind.test", "core-rtr-01", "128.66.16", "3fff:16",
                 "ACME", "Jane Smith", "netops", "0011.2233.4455"):
        assert leak not in out, leak


def test_vendor_support_keeps_the_serial_a_tac_case_needs():
    cfg = load(DOCS / "examples" / "02-vendor-support.toml")
    assert cfg.action_for_rule("serial-number") == "keep"
    assert cfg.action_for_rule("certificate-block") != "keep"
    text = ("! Serial Number: FDO1234ABCD\n"
            "snmp-server contact noc@northwind.test\n")
    result = sanitise_text(text, cfg, salt=SALT)
    assert "FDO1234ABCD" in result.text
    assert "noc@northwind.test" not in result.text
    assert result.findings == []


def test_external_review_hashes_free_text_but_keeps_it_distinguishable(cisco):
    cfg = load(DOCS / "examples" / "03-external-review.toml")
    out = sanitise_text(cisco, cfg, salt=SALT).text
    assert "ACME" not in out
    markers = {line.split()[-1] for line in out.splitlines()
               if line.strip().startswith("description <DESC-")}
    assert len(markers) == 2, "two different descriptions must stay different"


def test_custom_rules_example_works():
    cfg = load(DOCS / "examples" / "06-custom-rules.toml")
    text = ("acme shared-key TopSecret1\n"
            " api-token abcdef123456\n"
            "site-notes rack 12, contact Bob\n"
            "vault-ref prod/tacacs for core-switches\n"
            "snmp-server location Rack A12\n"
            "snmp {\n"
            "    acme-token hunter2;\n"
            "}\n"
            "acme-token not-in-snmp\n")
    result = sanitise_text(text, cfg, salt=SALT)
    out = result.text
    assert "TopSecret1" not in out and "abcdef123456" not in out
    assert "rack 12" not in out
    assert "site-notes <DESC-" in out                  # a text-family custom rule
    assert "vault-ref <REMOVED> for <REMOVED>" in out  # %VAL%, twice
    assert "acme-token <REMOVED>;" in out              # inside the snmp stanza
    assert "acme-token not-in-snmp" in out             # and only there
    # location is kept by name in that example
    assert "snmp-server location Rack A12" in out
    assert result.findings == []


def test_custom_rules_example_teaches_the_verifier_its_own_shape():
    cfg = load(DOCS / "examples" / "06-custom-rules.toml")
    text = "asset-tag ACME-ASSET-0123456789ABCDEF0123456789\n"
    assert sanitise_text(text, cfg, salt=SALT).findings == []


def test_generated_docs_are_up_to_date():
    rc = subprocess.run([sys.executable, "tools/gen_docs.py", "--check"],
                        cwd=ROOT, capture_output=True, text=True)
    assert rc.returncode == 0, rc.stdout + rc.stderr


def test_public_api_docs_do_not_use_removed_policy_family_keys():
    """Family sections replaced [policy] keys and cfg.policy attributes."""
    pages = (DOCS / "library.md", DOCS / "verification.md")
    removed = re.compile(
        r"\[policy\]\s+(?:text|secrets|identity)\b"
        r"|cfg\.policy\.(?:text|secrets|identity)\b"
        r'|\{"policy":\s*\{"(?:text|secrets|identity)"'
    )
    for path in pages:
        assert removed.search(path.read_text()) is None, path


@pytest.mark.parametrize("name", [
    "README.md", "getting-started.md", "configuration.md",
    "address-classes.md", "rules.md", "verification.md", "library.md",
])
def test_doc_page_exists_and_is_not_a_stub(name):
    path = DOCS / name
    assert path.is_file(), f"missing docs/{name}"
    assert len(path.read_text()) > 400, f"docs/{name} looks like a stub"


def test_the_design_note_exists():
    path = DOCS / "design" / "actions-model.md"
    assert path.is_file()
    assert len(path.read_text()) > 400
