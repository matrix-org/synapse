# -*- coding: utf-8 -*-

import re

MIME_TYPE_RE = re.compile(
    r"""
    ^
    ([\w\-]+)      # type grouping
    /              # literal slash
    ([\w\-]+)      # subtype grouping
    (              # all parameters grouping
        (          # individual parameter group
            ;\s*   # literal semicolon followed by some whitespace
            [^ ]+  # parameter name
            =      # literal equals
            [^;]+  # parameter value
        )*         # zero or more parameters
    )
    $""",
    re.VERBOSE,
)


class MimeType(object):
    """Implements parsing and normalization of IANA media type strings.

    See RFC 6838 for the full specification.
    """

    def __init__(self, iana_media_type: str):
        match = MIME_TYPE_RE.match(iana_media_type)
        if match is None:
            raise ValueError("Invalid media type string '{}'".format(iana_media_type))
        self.type = match.group(1).lower()
        self.subtype = match.group(2).lower()
        self.parameters = match.group(3) or ""
        self._normalize()

    def _normalize(self):
        if self.type == "image" and self.subtype == "jpg":
            self.subtype = "jpeg"

    def __str__(self) -> str:
        return "{}/{}{}".format(self.type, self.subtype, self.parameters)

    def __eq__(self, other) -> bool:
        if isinstance(other, MimeType):
            return (
                self.type == other.type
                and self.subtype == other.subtype
                and self.parameters == other.parameters
            )
        elif isinstance(other, str):
            return str(self) == other
        return False
