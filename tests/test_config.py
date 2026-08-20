"""The configuration model: selectors, actions, and what is no longer allowed."""

import pytest

from netredact import (
    ACTIONS,
    ALLOWED,
    FAMILIES,
    Config,
    ConfigError,
    CustomRule,
    RuleCatalogue,
    find_config,
)
from netredact.config import RULE_SECTIONS

from .conftest import SALT, policy

_RULES = RuleCatalogue.builtins().inventory()


def rule_names():
    return [info.name for info in _RULES]


def family_of(name):
    return next(info.family for info in _RULES if info.name == name)


def load(tmp_path, body: str) -> Config:
    p = tmp_path / "netredact.toml"
    p.write_text(body)
    return Config.load(p)


# -- the vocabulary ---------------------------------------------------------

def test_actions_and_families():
    assert ACTIONS == ("keep", "pseudo", "hash", "redact")
    assert FAMILIES == ("secrets", "text", "locations", "identity", "platform",
                        "interfaces", "vlans", "circuits",
                        "hostnames", "domains", "usernames", "emails",
                        "ipv4", "ipv6", "macs")


def test_pseudo_on_secrets_is_the_only_illegal_cell():
    illegal = {(family, action) for family in FAMILIES for action in ACTIONS
               if action not in ALLOWED[family]}
    assert illegal == {("secrets", "pseudo")}


def test_defaults_act_on_secrets_only():
    cfg = Config()
    assert cfg.secrets.default == "redact"
    assert all(cfg.action_for_rule(r) == "redact"
               for r in RULE_SECTIONS["secrets"].RULES)
    for family in ("text", "locations", "identity", "platform", "hostnames", "domains",
                   "usernames", "emails"):
        assert cfg.action_for(family) == "keep", family
    for family in ("text", "locations", "identity", "platform"):
        assert not getattr(cfg, family).any_active(), family
    assert cfg.ipv4.default == "keep" and not cfg.ipv4.any_active()
    assert cfg.ipv6.default == "keep" and not cfg.ipv6.any_active()
    assert cfg.macs.oui == cfg.macs.nic == "keep"
    assert not cfg.macs.any_active()
    assert cfg.custom == []


def test_every_ipv4_class_inherits_default():
    cfg = Config()
    cfg.ipv4.default = "pseudo"
    cfg.ipv4.rfc1918 = "keep"
    assert cfg.ipv4.action("other_unicast") == "pseudo"
    assert cfg.ipv4.action("rfc1918") == "keep"
    assert cfg.ipv4.any_active()


def test_unknown_address_class_is_rejected():
    with pytest.raises(ConfigError, match="unknown IPv4 address class"):
        Config().ipv4.action("rfc1917")
    with pytest.raises(ConfigError, match="unknown IPv6 address class"):
        Config().ipv6.action("cgnat")


# -- resolution -------------------------------------------------------------

def test_action_for_rule_follows_the_family():
    cfg = policy(text="redact", identity="hash")
    assert cfg.action_for_rule("enable-secret") == "redact"     # secrets
    assert cfg.action_for_rule("description") == "redact"       # text
    assert cfg.action_for_rule("serial-number") == "hash"       # identity


def test_a_named_rule_beats_its_section_default():
    cfg = Config(locations=RULE_SECTIONS["locations"](default="keep", location="redact"),
                 secrets=RULE_SECTIONS["secrets"](default="redact",
                                                  enable_secret="keep"))
    assert cfg.action_for_rule("location") == "redact"
    assert cfg.action_for_rule("contact") == "keep"             # section default
    assert cfg.action_for_rule("enable-secret") == "keep"


def test_action_for_macs_reads_both_halves():
    cfg = Config()
    cfg.macs.oui = "redact"
    cfg.macs.nic = "pseudo"
    assert cfg.macs.any_active()
    assert cfg.macs.oui == "redact" and cfg.macs.nic == "pseudo"


def test_action_for_rejects_an_unknown_family():
    with pytest.raises(ConfigError, match="unknown family"):
        Config().action_for("passwords")


def test_action_for_rule_rejects_an_unknown_rule():
    with pytest.raises(ConfigError, match="unknown rule name"):
        Config().action_for_rule("no-such-rule")


# -- loading ----------------------------------------------------------------

def test_load_from_toml(tmp_path):
    cfg = load(tmp_path, """
vendor = "juniper"
salt_file = "/tmp/netredact-salt"

[secrets]
default = "hash"

[ipv4]
default = "pseudo"
rfc1918 = "keep"
pool    = ["198.18.0.0/15"]

[macs]
oui = "keep"
nic = "pseudo"

[text]
default = "redact"

[locations]
default = "redact"
location = "keep"
""")
    assert cfg.vendor == "juniper"
    assert cfg.secrets.default == "hash"
    assert cfg.text.default == "redact"
    assert cfg.ipv4.action("other_unicast") == "pseudo"
    assert cfg.ipv4.action("rfc1918") == "keep"
    assert cfg.ipv4.pool == ["198.18.0.0/15"]
    assert cfg.macs.nic == "pseudo"
    assert cfg.action_for_rule("location") == "keep"
    assert cfg.salt_path().name == "netredact-salt"
    assert cfg.source == str(tmp_path / "netredact.toml")


def test_partial_config_keeps_other_defaults(tmp_path):
    cfg = load(tmp_path, '[ipv4]\ndefault = "pseudo"\n')
    assert cfg.ipv4.default == "pseudo"
    assert cfg.ipv4.pool == ["198.18.0.0/15", "100.64.0.0/10"]
    assert cfg.ipv4.well_known_resolvers[0] == "8.8.8.8"
    assert cfg.ipv6.well_known_resolvers[0] == "2001:4860:4860::8888"
    assert cfg.secrets.default == "redact"
    assert cfg.verify.enabled is True


def test_custom_rule_from_toml(tmp_path):
    cfg = load(tmp_path, """
[[custom]]
name    = "acme-shared-key"
pattern = '\\s*acme\\s+shared-key\\s+'
family  = "secrets"
stanza  = "snmp"
""")
    assert cfg.custom == [CustomRule(name="acme-shared-key",
                                     pattern=r"\s*acme\s+shared-key\s+",
                                     family="secrets", stanza="snmp")]
    assert cfg.action_for_rule("acme-shared-key") == "redact"


def test_custom_rule_family_drives_its_action():
    cfg = Config(custom=[CustomRule(name="site-notes", pattern=r"\s*site-notes\s+",
                                    family="text")])
    assert cfg.action_for_rule("site-notes") == "keep"          # text is kept
    cfg = Config(text=RULE_SECTIONS["text"](default="redact"),
                 custom=[CustomRule(name="site-notes", pattern=r"\s*site-notes\s+",
                                    family="text")])
    assert cfg.action_for_rule("site-notes") == "redact"


def test_a_custom_rule_can_carry_its_own_action():
    cfg = Config(custom=[CustomRule(name="acme-key", pattern="x",
                                    action="hash")])
    assert cfg.action_for_rule("acme-key") == "hash"            # not <REMOVED>
    assert cfg.action_for_rule("enable-secret") == "redact"     # family default


@pytest.mark.parametrize("body,message", [
    ('[secrets]\ndefault = "pseudo"\n', "pseudo is not available for secrets"),
    ('[secrets]\ndefault = "destroy"\n', "unknown action 'destroy'"),
    ('[secrets]\nno-such-rule = "keep"\n', r"unknown key\(s\) no-such-rule"),
    ('[secrets]\nenable-secret = "pseudo"\n',
     "pseudo is not available for secrets"),
    ('[locations]\nlocation = true\n', "must be a string"),
    ('[policy]\nnope = "keep"\n', r"unknown key\(s\) nope"),
    ('[nope]\nx = 1\n', "unknown top-level section"),
    ('[ipv4]\nrfc1917 = "keep"\n', r"unknown key\(s\) rfc1917"),
    ('[ipv4]\nrfc1918 = "yes please"\n', "unknown action"),
    ('[ipv4]\npool = "198.18.0.0/15"\n', r"\[ipv4\] pool must be a list"),
    ('[ipv6]\ndefault = true\n', r"\[ipv6\] default must be a string"),
    ('[macs]\noui = "hash"\nnic = "pseudo"\n',
     "hash applies to the whole address"),
    ('[[custom]]\nname = "x"\npattern = "y"\nfamily = "nope"\n',
     "family must be one of"),
    ('[[custom]]\nname = "x"\n', "missing 1 required positional argument"),
    ('[[custom]]\nname = "x"\npattern = 5\n', "pattern must be a string"),
    ('custom = { name = "x" }\n', r"use \[\[custom\]\] for each one"),
    ('vendor = "brocade"\n', "vendor must be one of"),
    ('[verify]\nstrict = "yes"\n', "must be true or false"),
    ('[verify]\ndisable = "credential-left"\n', "must be a list"),
])
def test_invalid_config_is_rejected(tmp_path, body, message):
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, body)


def test_unknown_key_error_names_the_expected_keys(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, '[policy]\nhostname = "redact"\n')
    assert "unknown key(s) hostname" in str(exc.value)
    assert "Expected: " in str(exc.value)
    assert "hostnames" in str(exc.value)

    # a rule section names its rules the same way, in their own spelling
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, '[identity]\nserial_number = "keep"\n')
    assert "unknown key(s) serial_number" in str(exc.value)
    assert "serial-number" in str(exc.value)


# -- the wrong section ------------------------------------------------------
#
# THE PRINCIPLE: a key that names a real rule is not a typo, it is a filing
# mistake. `[text] serial-number` is legal in every respect except its address:
# the rule exists, the action is legal, and the section's own key list answers a
# question this user did not ask. The one useful thing to say is where the rule
# does live. Listing the section's keys stays the right answer for a key that
# names nothing at all, and a config can contain both mistakes at once.

def test_a_rule_in_the_wrong_section_names_the_section_it_belongs_to(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, '[text]\nserial-number = "keep"\n')
    message = str(exc.value)
    assert "serial-number is a rule in [identity], not in [text]" in message
    assert "set it as [identity] serial-number" in message
    assert "Expected: " not in message, "the key list is not the answer here"


def test_a_misfiled_key_is_routed_in_the_spelling_the_user_wrote(tmp_path):
    """The field is `serial_number`; the rule, and the message, are kebab-case."""
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, '[text]\nserial_number = "keep"\n')
    message = str(exc.value)
    assert "serial_number is a rule in [identity]" in message
    assert "set it as [identity] serial-number" in message


def test_a_key_that_is_no_rule_at_all_still_lists_the_sections_keys(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, '[text]\nserial-numbers = "keep"\n')
    message = str(exc.value)
    assert "unknown key(s) serial-numbers" in message
    assert "Expected: acl-remark, banner" in message
    assert "belongs" not in message and "is a rule in" not in message


def test_a_misfiled_rule_and_a_typo_are_both_reported(tmp_path):
    """Several wrong keys in one section: each gets the answer it deserves."""
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, '[text]\nserial-number = "keep"\nos-version = "hash"\n'
                       'nosuch = "keep"\n')
    message = str(exc.value)
    assert "serial-number is a rule in [identity]" in message
    assert "os-version is a rule in [platform]" in message
    assert "unknown key(s) nosuch. Expected: " in message
    # the typo is listed once, as a typo, and not as a rule
    assert "nosuch is a rule" not in message


@pytest.mark.parametrize("rule", sorted(rule_names()))
def test_every_rule_is_routed_home_from_a_foreign_section(tmp_path, rule):
    """The anti-drift half: both the rule and its home come from the rule table.

    A rule refiled between families takes its own routing message with it, and
    a family added to ``RULE_SECTIONS`` is swept the day it exists -- there is
    no list here to keep in step.
    """
    home = family_of(rule)
    elsewhere = next(f for f in RULE_SECTIONS if f != home)
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, f'[{elsewhere}]\n{rule} = "keep"\n')
    assert f"set it as [{home}] {rule}" in str(exc.value)


def test_a_custom_rule_named_in_a_family_section_is_routed_to_its_own_entry(tmp_path):
    """A custom rule is a rule to its author, but its action is its own key."""
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, """
[secrets]
acme-shared-key = "hash"

[[custom]]
name    = "acme-shared-key"
pattern = '\\s*acme\\s+shared-key\\s+'
""")
    message = str(exc.value)
    assert "acme-shared-key is a [[custom]] rule" in message
    assert "its own [[custom]] entry" in message


# -- migration off the old model --------------------------------------------

@pytest.mark.parametrize("body,message", [
    ('[scrub]\nhostnames = true\n', r"\[scrub\] was replaced by \[policy\]"),
    ('[redact]\ndescriptions = "hash"\n',
     r"\[redact\] was replaced by the family sections"),
    ('[overrides]\nlocation = "keep"\n', r"\[overrides\] is gone"),
    ('[policy]\nsecrets = "redact"\n', r"now \[secrets\] default"),
    ('[ips]\npools_v4 = ["198.18.0.0/15"]\n',
     r"\[ips\] was replaced by \[ipv4\] and \[ipv6\]"),
    ('[[custom]]\nname = "x"\npattern = "y"\nmode = "value"\n',
     "mode was replaced by family"),
])
def test_removed_keys_give_a_migration_message(tmp_path, body, message):
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, body)


@pytest.mark.parametrize("body,hint", [
    ('[scrub]\nipv4 = true\n', "now [ipv4] default"),
    ('[scrub]\nmacs = "oui"\n', "now [macs] oui / nic"),
    ('[redact]\nbanners = "redact"\n', '[text] banner = "redact"'),
    ('[overrides]\nserial-number = "keep"\n', "now [identity] serial-number"),
    ('[redact]\ndisable = ["location"]\n', "disabling is an action now"),
    ('[redact]\ncustom = []\n', "now top-level [[custom]] entries"),
    ('[ips]\npool_v6 = "2001:db8::/32"\n', "now [ipv6] pool"),
    ('[ips]\nwell_known = []\n', "well_known_resolvers"),
    ('[ips]\nkeep_networks = []\n', "now [ipv4] keep_networks"),
])
def test_migration_message_names_the_replacement(tmp_path, body, hint):
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, body)
    assert hint in str(exc.value)


def test_custom_rule_has_no_mode_field():
    with pytest.raises(TypeError):
        CustomRule(name="x", pattern="y", mode="value")


# -- custom rules -----------------------------------------------------------

def test_custom_rule_needs_a_name_and_a_pattern():
    with pytest.raises(ConfigError, match="needs a name"):
        CustomRule(name="", pattern="x")
    with pytest.raises(ConfigError, match="needs a pattern"):
        CustomRule(name="x", pattern="")


def test_custom_rule_bad_regex_is_reported():
    with pytest.raises(ConfigError, match="bad regex"):
        Config(custom=[CustomRule(name="bad", pattern=r"(unclosed")])


def test_custom_rule_regex_overflow_is_a_config_error():
    with pytest.raises(ConfigError, match="bad regex"):
        Config(custom=[CustomRule(
            name="too-large",
            pattern="a{999999999999999999999999}",
        )])


def test_custom_rule_cannot_pseudonymise_a_secret():
    with pytest.raises(ConfigError, match="pseudo is not available for secrets"):
        Config(custom=[CustomRule(name="x", pattern="y", family="secrets",
                                  action="pseudo")])


def test_validate_rejects_mutation_before_sanitisation():
    from netredact import sanitise_text

    cfg = Config()
    cfg.policy.hostnames = 3
    with pytest.raises(ConfigError, match=r"\[policy\] hostnames must be an action string"):
        cfg.validate()
    with pytest.raises(ConfigError, match=r"\[policy\] hostnames must be an action string"):
        sanitise_text("hostname edge-1\n", cfg, salt=SALT)


def test_the_lower_level_sanitiser_validates_before_collection():
    from netredact import Sanitiser

    cfg = Config()
    cfg.text.default = "shred"
    with pytest.raises(ConfigError, match="unknown action 'shred'"):
        Sanitiser(cfg, salt=SALT)


@pytest.mark.parametrize("mutate,message", [
    (lambda cfg: setattr(cfg.ipv4, "pool", ["198.18.0.0/15", 7]),
     r"\[ipv4\] pool entries must be strings"),
    (lambda cfg: setattr(cfg.verify, "disable", ["credential-left", 7]),
     r"\[verify\] disable entries must be strings"),
    (lambda cfg: setattr(cfg.verify, "ignore_patterns", [r"(unclosed"]),
     r"\[verify\] ignore_patterns.*bad regex"),
    (lambda cfg: setattr(cfg, "salt_file", 7),
     "salt_file must be a string or null"),
    (lambda cfg: setattr(cfg, "vendor", 7),
     "vendor must be a string"),
])
def test_validate_normalises_invalid_field_errors(mutate, message):
    cfg = Config()
    mutate(cfg)
    with pytest.raises(ConfigError, match=message):
        cfg.validate()


def test_duplicate_custom_rules_are_config_errors():
    with pytest.raises(ConfigError, match="duplicate rule name"):
        Config(custom=[
            CustomRule(name="same", pattern="first"),
            CustomRule(name="same", pattern="second"),
        ])
    with pytest.raises(ConfigError, match="duplicate rule name"):
        Config(custom=[CustomRule(name="enable-secret", pattern="shadow")])


@pytest.mark.parametrize("raw,message", [
    (7, "configuration must be a table"),
    ({"vendor": 7}, "vendor must be a string"),
    ({"salt_file": 7}, "salt_file must be a string or null"),
    ({"custom": [7]}, r"\[\[custom\]\] entries must be tables"),
    ({"custom": [{"name": 7, "pattern": "x"}]},
     r"\[\[custom\]\] name must be a string"),
])
def test_programmatic_top_level_and_custom_types_raise_config_error(raw, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_dict(raw)


@pytest.mark.parametrize("raw,message", [
    ({7: "value"}, "top-level keys must be strings"),
    ({"policy": {7: "keep"}}, r"\[policy\] keys must be strings"),
    ({"custom": [{7: "value"}]}, r"\[custom\] keys must be strings"),
])
def test_non_string_configuration_keys_raise_config_error(raw, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_dict(raw)


# -- pools ------------------------------------------------------------------

@pytest.mark.parametrize("pool,message", [
    ([], "ipv4.pool must not be empty"),
    (["198.18.0.0/25"], "ipv4.pool entries must be /24 or shorter"),
    (["2001:db8::/32"], "ipv4.pool must be IPv4"),
])
def test_ipv4_pool_validation_names_the_new_key(pool, message):
    from netredact import sanitise_text
    cfg = Config()
    cfg.ipv4.pool = pool
    with pytest.raises(ValueError, match=message):
        sanitise_text("hostname x\n", cfg, salt=SALT)


def test_ipv6_pool_validation_names_the_new_key():
    from netredact import sanitise_text
    cfg = Config()
    cfg.ipv6.pool = "2001:db8::/96"
    with pytest.raises(ValueError, match="ipv6.pool must be /64 or shorter"):
        sanitise_text("hostname x\n", cfg, salt=SALT)


# -- emitting ---------------------------------------------------------------

def test_round_trips_through_print_config(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(Config().to_toml())
    assert Config.load(p) == Config(source=str(p))


def test_to_toml_documents_every_rule_family_key():
    body = Config().to_toml()
    for family in ("secrets", "text", "identity", "hostnames",
                   "domains", "usernames", "emails"):
        assert f"{family} " in body or f"{family}=" in body
    assert "[ipv4]" in body and "[ipv6]" in body and "[macs]" in body
    assert "[platform]" in body
    for rule in RULE_SECTIONS['platform'].RULES:
        assert rule in body, rule
    assert "well_known_resolvers" in body
    assert "[[custom]]" in body


def test_find_config_prefers_cwd(tmp_path, monkeypatch):
    (tmp_path / "netredact.toml").write_text("")
    monkeypatch.chdir(tmp_path)
    assert find_config() == tmp_path / "netredact.toml"


def test_every_builtin_rule_is_reachable_from_its_section():
    """Nothing is unreachable: every rule has a key, and exactly one."""
    sections = {family: RULE_SECTIONS[family](
        default="keep",
        **{n.replace("-", "_"): "keep" for n in RULE_SECTIONS[family].RULES})
        for family in RULE_SECTIONS}
    cfg = Config(**sections)
    assert all(cfg.action_for_rule(name) == "keep" for name in rule_names())
    homes = [f for name in rule_names()
             for f in RULE_SECTIONS if name in RULE_SECTIONS[f].RULES]
    assert len(homes) == len(rule_names())
