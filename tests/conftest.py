from pathlib import Path

import pytest

from netredact import Config, PolicyConfig

FIXTURES = Path(__file__).parent / "fixtures"

#: every shipped fixture, by file name
FIXTURE_NAMES = ("cisco.cfg", "arista.cfg", "juniper.cfg",
                 "edge.cfg", "edge-junos.cfg", "qk.cfg")


@pytest.fixture
def fixtures():
    return FIXTURES


def read(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def cisco():
    return read("cisco.cfg")


@pytest.fixture
def arista():
    return read("arista.cfg")


@pytest.fixture
def juniper():
    return read("juniper.cfg")


@pytest.fixture
def edge():
    return read("edge.cfg")


@pytest.fixture
def edge_junos():
    return read("edge-junos.cfg")


@pytest.fixture
def qk():
    return read("qk.cfg")


SALT = b"deterministic-test-salt-do-not-use-in-anger"


# -- isolation ---------------------------------------------------------------

@pytest.fixture(autouse=True)
def hermetic_config(tmp_path_factory, monkeypatch):
    """No test may discover a real configuration file.

    THE PRINCIPLE: a test asserts against a policy it states. ``find_config``
    searches three places -- the cwd, ``$XDG_CONFIG_HOME/netredact`` and
    ``~/.config/netredact`` -- so without this any of them silently rewrites
    that policy. A ``netredact.toml`` left in the repository root is the one
    that bites in practice; a developer's own config in ``$HOME`` is the one
    that bites mysteriously, because it differs per machine and can name a
    ``salt_file``, which would make CLI output depend on a real
    re-identification key.

    Every search path is pointed at an empty temporary directory, so
    :meth:`Config.load` falls through to the built-in defaults. A test that is
    *about* discovery re-points the cwd itself and still works.

    These directories deliberately do NOT live under the test's own
    ``tmp_path``: tests that assert on the contents of ``tmp_path`` would count
    them as output files.
    """
    base = tmp_path_factory.mktemp("hermetic")
    home = base / "home"
    (home / ".config").mkdir(parents=True)
    cwd = base / "cwd"
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.chdir(cwd)


# -- configuration builders --------------------------------------------------
# The model is selector-then-action, so a test says which selector it is
# exercising and with which action; nothing else moves.

def policy(**actions) -> Config:
    """A config with the named ``[policy]`` families set, all else default."""
    return Config(policy=PolicyConfig(**actions))


def addresses(action: str = "pseudo", *, pool=("198.18.0.0/15",)) -> Config:
    """Every IPv4 and IPv6 class on one action.

    The pool is narrowed to the benchmark range by default so generated
    addresses never land in real CGNAT space and confuse an assertion.
    """
    cfg = Config()
    cfg.ipv4.default = action
    cfg.ipv6.default = action
    cfg.ipv4.pool = list(pool)
    return cfg


def maximal() -> Config:
    """Everything acts: the strongest policy the model can express."""
    cfg = policy(secrets="redact", text="redact", identity="redact",
                 hostnames="pseudo", domains="pseudo",
                 usernames="pseudo", emails="pseudo")
    cfg.ipv4.default = "pseudo"
    cfg.ipv6.default = "pseudo"
    cfg.ipv4.pool = ["198.18.0.0/15"]
    cfg.macs.oui = "redact"
    cfg.macs.nic = "pseudo"
    return cfg
