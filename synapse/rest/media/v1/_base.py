# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
            server_name = server_name.decode('utf-8')
            media_id = media_id.decode('utf8')

        file_name = None
        if len(request.postpath) > 2:
            try:
                file_name = urllib.parse.unquote(request.postpath[-1].decode("utf-8"))
            except UnicodeDecodeError:
                pass
        return server_name, media_id, file_name
    except Exception:
        raise SynapseError(
            404,
            "Invalid media id token %r" % (request.postpath,),
            Codes.UNKNOWN,
        )


def respond_404(request):
    respond_with_json(
        request, 404,
        cs_error(
            "Not found %r" % (request.postpath,),
            code=Codes.NOT_FOUND,
        ),
        send_cors=True
    )


@defer.inlineCallbacks
def respond_with_file(request, media_type, file_path,
                      file_size=None, upload_name=None):
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
        if is_ascii(upload_name):
            disposition = ("inline; filename=%s" % (_quote(upload_name),)).encode("ascii")
        else:
            disposition = (
                "inline; filename*=utf-8''%s" % (_quote(upload_name),)).encode("ascii")

        request.setHeader(b"Content-Disposition", disposition)

    # cache for at least a day.
    # XXX: we might want to turn this off for data we don't want to
    # recommend caching as it's sensitive or private - or at least
    # select private. don't bother setting Expires as all our
    # clients are smart enough to be happy with Cache-Control
    request.setHeader(
        b"Cache-Control", b"public,max-age=86400,s-maxage=86400"
    )

    request.setHeader(
        b"Content-Length", b"%d" % (file_size,)
    )


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
    with responder:
        yield responder.write_to_consumer(request)
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
    def __init__(self, server_name, file_id, url_cache=False,
                 thumbnail=False, thumbnail_width=None, thumbnail_height=None,
                 thumbnail_method=None, thumbnail_type=None):
        self.server_name = server_name
        self.file_id = file_id
        self.url_cache = url_cache
        self.thumbnail = thumbnail
        self.thumbnail_width = thumbnail_width
        self.thumbnail_height = thumbnail_height
        self.thumbnail_method = thumbnail_method
        self.thumbnail_type = thumbnail_type
