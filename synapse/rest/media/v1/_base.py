# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os

from six import PY3
from six.moves import urllib

from twisted.internet import defer
from twisted.protocols.basic import FileSender

from synapse.api.errors import Codes, SynapseError, cs_error
from synapse.http.server import finish_request, respond_with_json
from synapse.util import logcontext
from synapse.util.stringutils import is_ascii

logger = logging.getLogger(__name__)


def parse_media_id(request):
    try:
        # This allows users to append e.g. /test.png to the URL. Useful for
        # clients that parse the URL to see content type.
        server_name, media_id = request.postpath[:2]

        if isinstance(server_name, bytes):
            server_name = server_name.decode("utf-8")
            media_id = media_id.decode("utf8")

        file_name = None
        if len(request.postpath) > 2:
            try:
                file_name = urllib.parse.unquote(request.postpath[-1].decode("utf-8"))
            except UnicodeDecodeError:
                pass
        return server_name, media_id, file_name
    except Exception:
        raise SynapseError(
            404, "Invalid media id token %r" % (request.postpath,), Codes.UNKNOWN
        )


def respond_404(request):
    respond_with_json(
        request,
        404,
        cs_error("Not found %r" % (request.postpath,), code=Codes.NOT_FOUND),
        send_cors=True,
    )


@defer.inlineCallbacks
def respond_with_file(request, media_type, file_path, file_size=None, upload_name=None):
    logger.debug("Responding with %r", file_path)

    if os.path.isfile(file_path):
        if file_size is None:
            stat = os.stat(file_path)
            file_size = stat.st_size

        add_file_headers(request, media_type, file_size, upload_name)

        with open(file_path, "rb") as f:
            yield logcontext.make_deferred_yieldable(
                FileSender().beginFileTransfer(f, request)
            )

        finish_request(request)
    else:
        respond_404(request)


def add_file_headers(request, media_type, file_size, upload_name):
    """Adds the correct response headers in preparation for responding with the
    media.

    Args:
        request (twisted.web.http.Request)
        media_type (str): The media/content type.
        file_size (int): Size in bytes of the media, if known.
        upload_name (str): The name of the requested file, if any.
    """

    def _quote(x):
        return urllib.parse.quote(x.encode("utf-8"))

    request.setHeader(b"Content-Type", media_type.encode("UTF-8"))
    if upload_name:
        # RFC6266 section 4.1 [1] defines both `filename` and `filename*`.
        #
        # `filename` is defined to be a `value`, which is defined by RFC2616
        # section 3.6 [2] to be a `token` or a `quoted-string`, where a `token`
        # is (essentially) a single US-ASCII word, and a `quoted-string` is a
        # US-ASCII string surrounded by double-quotes, using backslash as an
        # escape charater. Note that %-encoding is *not* permitted.
        #
        # `filename*` is defined to be an `ext-value`, which is defined in
        # RFC5987 section 3.2.1 [3] to be `charset "'" [ language ] "'" value-chars`,
        # where `value-chars` is essentially a %-encoded string in the given charset.
        #
        # [1]: https://tools.ietf.org/html/rfc6266#section-4.1
        # [2]: https://tools.ietf.org/html/rfc2616#section-3.6
        # [3]: https://tools.ietf.org/html/rfc5987#section-3.2.1

        # We avoid the quoted-string version of `filename`, because (a) synapse didn't
        # correctly interpret those as of 0.99.2 and (b) they are a bit of a pain and we
        # may as well just do the filename* version.
        if _can_encode_filename_as_token(upload_name):
            disposition = "inline; filename=%s" % (upload_name,)
        else:
            disposition = "inline; filename*=utf-8''%s" % (_quote(upload_name),)

        request.setHeader(b"Content-Disposition", disposition.encode("ascii"))

    # cache for at least a day.
    # XXX: we might want to turn this off for data we don't want to
    # recommend caching as it's sensitive or private - or at least
    # select private. don't bother setting Expires as all our
    # clients are smart enough to be happy with Cache-Control
    request.setHeader(b"Cache-Control", b"public,max-age=86400,s-maxage=86400")
    request.setHeader(b"Content-Length", b"%d" % (file_size,))


# separators as defined in RFC2616. SP and HT are handled separately.
# see _can_encode_filename_as_token.
_FILENAME_SEPARATOR_CHARS = set(
    (
        "(",
        ")",
        "<",
        ">",
        "@",
        ",",
        ";",
        ":",
        "\\",
        '"',
        "/",
        "[",
        "]",
        "?",
        "=",
        "{",
        "}",
    )
)


def _can_encode_filename_as_token(x):
    for c in x:
        # from RFC2616:
        #
        #        token          = 1*<any CHAR except CTLs or separators>
        #
        #        separators     = "(" | ")" | "<" | ">" | "@"
        #                       | "," | ";" | ":" | "\" | <">
        #                       | "/" | "[" | "]" | "?" | "="
        #                       | "{" | "}" | SP | HT
        #
        #        CHAR           = <any US-ASCII character (octets 0 - 127)>
        #
        #        CTL            = <any US-ASCII control character
        #                         (octets 0 - 31) and DEL (127)>
        #
        if ord(c) >= 127 or ord(c) <= 32 or c in _FILENAME_SEPARATOR_CHARS:
            return False
    return True


@defer.inlineCallbacks
def respond_with_responder(request, responder, media_type, file_size, upload_name=None):
    """Responds to the request with given responder. If responder is None then
    returns 404.

    Args:
        request (twisted.web.http.Request)
        responder (Responder|None)
        media_type (str): The media/content type.
        file_size (int|None): Size in bytes of the media. If not known it should be None
        upload_name (str|None): The name of the requested file, if any.
    """
    if not responder:
        respond_404(request)
        return

    logger.debug("Responding to media request with responder %s")
    add_file_headers(request, media_type, file_size, upload_name)
    try:
        with responder:
            yield responder.write_to_consumer(request)
    except Exception as e:
        # The majority of the time this will be due to the client having gone
        # away. Unfortunately, Twisted simply throws a generic exception at us
        # in that case.
        logger.warning("Failed to write to consumer: %s %s", type(e), e)

        # Unregister the producer, if it has one, so Twisted doesn't complain
        if request.producer:
            request.unregisterProducer()

    finish_request(request)


class Responder(object):
    """Represents a response that can be streamed to the requester.

    Responder is a context manager which *must* be used, so that any resources
    held can be cleaned up.
    """

    def write_to_consumer(self, consumer):
        """Stream response into consumer

        Args:
            consumer (IConsumer)

        Returns:
            Deferred: Resolves once the response has finished being written
        """
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class FileInfo(object):
    """Details about a requested/uploaded file.

    Attributes:
        server_name (str): The server name where the media originated from,
            or None if local.
        file_id (str): The local ID of the file. For local files this is the
            same as the media_id
        url_cache (bool): If the file is for the url preview cache
        thumbnail (bool): Whether the file is a thumbnail or not.
        thumbnail_width (int)
        thumbnail_height (int)
        thumbnail_method (str)
        thumbnail_type (str): Content type of thumbnail, e.g. image/png
    """

    def __init__(
        self,
        server_name,
        file_id,
        url_cache=False,
        thumbnail=False,
        thumbnail_width=None,
        thumbnail_height=None,
        thumbnail_method=None,
        thumbnail_type=None,
    ):
        self.server_name = server_name
        self.file_id = file_id
        self.url_cache = url_cache
        self.thumbnail = thumbnail
        self.thumbnail_width = thumbnail_width
        self.thumbnail_height = thumbnail_height
        self.thumbnail_method = thumbnail_method
        self.thumbnail_type = thumbnail_type


def get_filename_from_headers(headers):
    """
    Get the filename of the downloaded file by inspecting the
    Content-Disposition HTTP header.

    Args:
        headers (dict[bytes, list[bytes]]): The HTTP request headers.

    Returns:
        A Unicode string of the filename, or None.
    """
    content_disposition = headers.get(b"Content-Disposition", [b""])

    # No header, bail out.
    if not content_disposition[0]:
        return

    _, params = _parse_header(content_disposition[0])

    upload_name = None

    # First check if there is a valid UTF-8 filename
    upload_name_utf8 = params.get(b"filename*", None)
    if upload_name_utf8:
        if upload_name_utf8.lower().startswith(b"utf-8''"):
            upload_name_utf8 = upload_name_utf8[7:]
            # We have a filename*= section. This MUST be ASCII, and any UTF-8
            # bytes are %-quoted.
            if PY3:
                try:
                    # Once it is decoded, we can then unquote the %-encoded
                    # parts strictly into a unicode string.
                    upload_name = urllib.parse.unquote(
                        upload_name_utf8.decode("ascii"), errors="strict"
                    )
                except UnicodeDecodeError:
                    # Incorrect UTF-8.
                    pass
            else:
                # On Python 2, we first unquote the %-encoded parts and then
                # decode it strictly using UTF-8.
                try:
                    upload_name = urllib.parse.unquote(upload_name_utf8).decode("utf8")
                except UnicodeDecodeError:
                    pass

    # If there isn't check for an ascii name.
    if not upload_name:
        upload_name_ascii = params.get(b"filename", None)
        if upload_name_ascii and is_ascii(upload_name_ascii):
            upload_name = upload_name_ascii.decode("ascii")

    # This may be None here, indicating we did not find a matching name.
    return upload_name


def _parse_header(line):
    """Parse a Content-type like header.

    Cargo-culted from `cgi`, but works on bytes rather than strings.

    Args:
        line (bytes): header to be parsed

    Returns:
        Tuple[bytes, dict[bytes, bytes]]:
            the main content-type, followed by the parameter dictionary
    """
    parts = _parseparam(b";" + line)
    key = next(parts)
    pdict = {}
    for p in parts:
        i = p.find(b"=")
        if i >= 0:
            name = p[:i].strip().lower()
            value = p[i + 1 :].strip()

            # strip double-quotes
            if len(value) >= 2 and value[0:1] == value[-1:] == b'"':
                value = value[1:-1]
                value = value.replace(b"\\\\", b"\\").replace(b'\\"', b'"')
            pdict[name] = value

    return key, pdict


def _parseparam(s):
    """Generator which splits the input on ;, respecting double-quoted sequences

    Cargo-culted from `cgi`, but works on bytes rather than strings.

    Args:
        s (bytes): header to be parsed

    Returns:
        Iterable[bytes]: the split input
    """
    while s[:1] == b";":
        s = s[1:]

        # look for the next ;
        end = s.find(b";")

        # if there is an odd number of " marks between here and the next ;, skip to the
        # next ; instead
        while end > 0 and (s.count(b'"', 0, end) - s.count(b'\\"', 0, end)) % 2:
            end = s.find(b";", end + 1)

        if end < 0:
            end = len(s)
        f = s[:end]
        yield f.strip()
        s = s[end:]
