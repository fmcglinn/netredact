"""Remove non-configuration command output from RANCID captures."""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["RemovedSection", "strip_rancid_diagnostics"]


@dataclass(frozen=True)
class RemovedSection:
    """One collector command section physically removed from the input."""

    command: str
    lines: int


_RANCID_HEADER = re.compile(r"^\s*[#!;]\s*RANCID-CONTENT-TYPE\s*:", re.I)
_COMMAND_HEADER = re.compile(r"^\s*!\s*Command\s*:\s*(.+?)\s*$", re.I)
_PROMPT = re.compile(
    r"^\s*(?:[#!;]\s*)?([A-Za-z0-9_.%+:-]+)@(\S+)([>#])[ \t]+(.+?)[ \t]*$",
    re.I,
)
_ARISTA_DEVICE = re.compile(r"^\s*!\s*device\s*:", re.I)


def _normalise(command: str) -> str:
    return " ".join(command.strip().split()).lower()


def _is_configuration_command(command: str) -> bool:
    command = _normalise(command)
    return command in {
        "show configuration",
        "show configuration | display set",
        "show running-config",
        "show startup-config",
    }


def strip_rancid_diagnostics(lines: list[str]) -> tuple[list[str], list[RemovedSection]]:
    """Return configuration-bearing lines and an audit of deleted sections.

    Detection is intentionally strong: an explicit RANCID header, a RANCID-style
    ``! Command:`` header, or at least two commented CLI prompts. Once detected,
    command output fails closed and only allowlisted configuration commands remain.
    """
    prompt_matches = [(i, m) for i, line in enumerate(lines)
                      if (m := _PROMPT.match(line))]
    if prompt_matches:
        first_identity = tuple(value.lower() for value in
                               prompt_matches[0][1].group(1, 2))
        prompt_matches = [
            (i, match) for i, match in prompt_matches
            if tuple(value.lower() for value in match.group(1, 2)) == first_identity
        ]
    prompts = [(i, match.group(4)) for i, match in prompt_matches]
    headers = [(i, m.group(1)) for i, line in enumerate(lines)
               if (m := _COMMAND_HEADER.match(line))]
    detected = (any(_RANCID_HEADER.match(line) for line in lines)
                or bool(headers) or len(prompts) >= 2)
    if not detected:
        return lines, []

    boundaries = sorted(
        [(i, command, "prompt") for i, command in prompts]
        + [(i, command, "header") for i, command in headers]
    )
    if not boundaries:
        # This is the output of an earlier stripping pass: it retains the
        # content-type header and configuration, but no collector boundaries.
        # Treat it as configuration so preprocessing is idempotent. A malformed
        # diagnostic section still has its opening prompt and is handled below.
        return lines, []

    header_lines = [line for line in lines[:boundaries[0][0]]
                    if _RANCID_HEADER.match(line)]
    preamble_count = boundaries[0][0] - len(header_lines)
    out: list[str] = list(header_lines)
    removed: list[RemovedSection] = []
    if preamble_count:
        removed.append(RemovedSection("collector preamble", preamble_count))
    metadata_count = 0
    allowed_count = sum(_is_configuration_command(command)
                        for _start, command, _kind in boundaries)
    marker = "#" if any("juniper" in line.lower() for line in header_lines) else "!"
    for position, (start, command, kind) in enumerate(boundaries):
        end = boundaries[position + 1][0] if position + 1 < len(boundaries) else len(lines)
        if _is_configuration_command(command):
            body = list(lines[start + 1:end])
            metadata_count += 1  # the prompt / command header itself
            if kind == "header":
                while body and (_ARISTA_DEVICE.match(body[0])
                                or body[0].strip() in {"!", "#", ";"}):
                    body.pop(0)
                    metadata_count += 1
            if allowed_count > 1:
                out.append(f"{marker} source: {_normalise(command)}")
            out.extend(body)
        else:
            removed.append(RemovedSection(_normalise(command), end - start))

    if metadata_count:
        removed.append(RemovedSection("collector metadata", metadata_count))

    return out, removed
