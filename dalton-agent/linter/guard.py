"""Reject anything in a rule buffer that the Suricata Language Server would
act on beyond ordinary rule syntax checking, before SLS ever sees the text.

SLS is built for a developer editing a file on their own machine and reads
directives straight out of the buffer on that assumption
(signature_validator.py in the SLS source):

  ## SLS suricata-options:   -> shlex.split() straight onto the Suricata argv
  ## SLS pcap-file:          -> reads a file off disk and runs Suricata against it
  ## SLS replace:            -> rewrites the buffer via re.sub
  ## SLS dataset-dir: / suricata-version: -> path and image-tag control

It also copies any `lua:<path>.lua;` (or `luajit:`) target that exists on
disk next to the rules.

This module has no heavy imports so it can be unit tested without Suricata
or SLS installed. Match MORE loosely than SLS's own directive regex
(`^##\\s*SLS\\s+`) - the point is that no buffer should be able to slip past
this guard and then be acted on by SLS, so when in doubt, reject.
"""

import re

SLS_DIRECTIVE = re.compile(r"^\s*##\s*SLS\b")
# Must not match 'luaxform:' - a real Suricata 8 keyword - so the colon has
# to follow directly (optionally through whitespace) after 'lua'/'luajit'.
LUA_KEYWORD = re.compile(r"\blua(?:jit)?\s*:")

MAX_BYTES = 64 * 1024
MAX_LINES = 200


class GuardRejection(Exception):
    """Raised with a human-readable reason; the caller turns this into a
    diagnostic anchored to the offending line rather than an HTTP error."""

    def __init__(self, message, line=0):
        super().__init__(message)
        self.message = message
        self.line = line


def check_rule_buffer(buffer):
    """Raise GuardRejection if `buffer` isn't safe to hand to SLS. Returns
    None on success."""
    size = len(buffer.encode("utf-8"))
    if size > MAX_BYTES:
        raise GuardRejection(
            f"Rule buffer is {size} bytes, over the {MAX_BYTES}-byte limit."
        )

    lines = buffer.splitlines()
    if len(lines) > MAX_LINES:
        raise GuardRejection(
            f"Rule buffer has {len(lines)} lines, over the {MAX_LINES}-line limit."
        )

    for lineno, line in enumerate(lines):
        if SLS_DIRECTIVE.match(line):
            raise GuardRejection(
                "'## SLS' directives are not permitted here; they let the "
                "checker read files, rewrite the buffer, or pass arguments "
                "straight to Suricata.",
                line=lineno,
            )
        if LUA_KEYWORD.search(line):
            raise GuardRejection(
                "lua:/luajit: keywords are not permitted here; they would "
                "load a Lua script from disk next to the rules.",
                line=lineno,
            )
