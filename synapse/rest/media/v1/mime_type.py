# -*- coding: utf-8 -*-

import re

MIME_TYPE_RE = re.compile(
    r"""
    ^
    ([\w\-]+)  # type
    /          # literal slash
    ([\w\-]+)  # subtype
    (          # parameters
        ;\s*   # literal semicolon followed by some whitespace
        [^ ]+  # parameter name
        =      # literal equals
        \w+    # parameter value
    )*         # zero or more parameters
    $""",
    re.VERBOSE,
)


class MimeType(object):
    """Implements parsing and normalization of IANA media type strings.

    See RFC 6838 for the full specification. Currently ignores mime type
    parameters (e.g. 'text/html; encoding="utf-8"').
    """

    def __init__(self, iana_media_type: str):
        match = MIME_TYPE_RE.match(iana_media_type.lower())
        if match is None:
            raise ValueError("Invalid media type string '{}'".format(iana_media_type))
        self.type = match.group(1)
        self.subtype = match.group(2)
        self._normalize()

    def _normalize(self):
        if self.type == "image" and self.subtype == "jpg":
            self.subtype = "jpeg"

    def __str__(self) -> str:
        return "{}/{}".format(self.type, self.subtype)

    def __eq__(self, other) -> bool:
        if isinstance(other, MimeType):
            return self.type == other.type and self.subtype == other.subtype
        elif isinstance(other, str):
            return str(self) == other
        return False
