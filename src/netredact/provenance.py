"""The line netredact writes at the top of its own output, and finding it again.

A sanitised file looks like a configuration, which is the point -- and the
problem. Nothing in the output says where it came from, so the one mistake it
invites is running netredact over it a second time. That is not a no-op: a
``pseudo`` substitute is deliberately indistinguishable from a real value,
including to netredact, so a second pass maps it again. Do that with
``--replace`` and the original is gone, along with any way to redo it.

So the output carries one comment line naming the tool, and every entry point
looks for it on the way in. The marker is what makes the second run
*refusable*: without it there is no evidence in the file to refuse on.

Three properties the marker has to have, all of them load-bearing:

* **It is a comment in the grammar it lands in.** ``#`` for JunOS, ``!``
  everywhere else, so the output still pastes onto a device.
* **It never passes through the rules.** :func:`strip` removes it before
  sanitising and the caller re-applies it afterwards, so the version number in
  it cannot be hashed by the ``os-version`` rule, it cannot be counted as a
  change, and a second pass over already-marked text is byte-identical to the
  first.
* **It carries nothing private.** The tool, the version, and a warning. No
  timestamp, no salt, no counts: a marker that leaked what was found, or when,
  would be a re-identification hint in the one file you intend to hand over.
"""

from __future__ import annotations

__all__ = ["TOKEN", "marker_for", "is_marked", "strip", "apply"]

#: the machine-readable half of the marker. Comment characters and wording
#: differ by vendor and may be reworded; this token is the contract, and
#: detection matches on it alone.
TOKEN = "netredact-sanitised"

#: how far into a file the token is looked for. The marker is the first line of
#: netredact's own output, so this only has to tolerate a header someone added
#: on top of it -- a ticket reference, a RANCID content-type line.
WINDOW = 10


def _comment(vendor: str) -> str:
    """The comment character for a vendor's grammar.

    JunOS and RouterOS comment with ``#``; IOS-style grammars use ``!``. An
    unknown vendor gets ``!``, which the ``set`` format also tolerates at the
    start of a line.
    """
    return "#" if vendor in ("juniper", "mikrotik") else "!"


def marker_for(vendor: str, version: str) -> str:
    """The marker line to write at the top of sanitised output."""
    return (f"{_comment(vendor)} {TOKEN} {version} -- sanitised output, not a "
            "device configuration; re-run from the original")


def is_marked(text: str) -> bool:
    """Whether this text carries netredact's marker, i.e. is already output."""
    return any(TOKEN in line for line in text.splitlines()[:WINDOW])


def strip(lines: list[str]) -> list[str]:
    """``lines`` without any marker line in the leading window.

    Every marker is removed, not just the first: a file that somehow collected
    two must not end up with three.
    """
    head = [line for line in lines[:WINDOW] if TOKEN not in line]
    return head + lines[WINDOW:]


def apply(lines: list[str], vendor: str, version: str) -> list[str]:
    """``lines`` with exactly one marker at the top."""
    return [marker_for(vendor, version)] + strip(lines)


def apply_text(text: str, vendor: str, version: str) -> str:
    """``text`` with exactly one marker at the top, trailing newline intact.

    This is what a caller that writes a file wants. :func:`sanitise_text`
    deliberately does not do it: a marker is a property of the artefact, not
    of the transformation, which promises to preserve line count.
    """
    if not text:
        return text
    out = "\n".join(apply(text.splitlines(), vendor, version))
    return out + "\n" if text.endswith("\n") else out
