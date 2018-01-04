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

import os

import logging
import urllib
import urlparse
import re
import fnmatch

from twisted.internet import defer
from twisted.protocols.basic import FileSender

from synapse.http.server import respond_with_json, finish_request
from synapse.api.errors import (
    cs_error, Codes, SynapseError
)
from synapse.util import logcontext
from synapse.util.stringutils import is_ascii


logger = logging.getLogger(__name__)


def validate_url_blacklist(blacklist, url):
    '''
    Preview and resolve endpoints would require to validate urls
    before to process it. In the configuration section the administrator
    should define blacklist urls to ensure that synapse users will not
    try to explore files using these api for restricted areas.
    '''
    url_tuple = urlparse.urlsplit(url)

    for entry in blacklist:
        match = True

        for attrib in entry:
            pattern = entry[attrib]
            value = getattr(url_tuple, attrib)
            logger.debug(
                "Matching attrib '%s' with value '%s' against"
                " pattern '%s'", attrib, value, pattern)

            if value is None:
                match = False
                continue

            if pattern.startswith('^'):
                if not re.match(pattern, getattr(url_tuple, attrib)):
                    match = False
                    continue
            else:
                if not fnmatch.fnmatch(getattr(url_tuple, attrib), pattern):
                    match = False
                    continue

            if match:
                logger.warn("URL %s blocked by url_blacklist entry %s", url, entry)
                return False
    return True


def parse_media_id(request):
    try:
        # This allows users to append e.g. /test.png to the URL. Useful for
        # clients that parse the URL to see content type.
        server_name, media_id = request.postpath[:2]
        file_name = None
        if len(request.postpath) > 2:
            try:
                file_name = urlparse.unquote(request.postpath[-1]).decode("utf-8")
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
        request.setHeader(b"Content-Type", media_type.encode("UTF-8"))
        if upload_name:
            if is_ascii(upload_name):
                request.setHeader(
                    b"Content-Disposition",
                    b"inline; filename=%s" % (
                        urllib.quote(upload_name.encode("utf-8")),
                    ),
                )
            else:
                request.setHeader(
                    b"Content-Disposition",
                    b"inline; filename*=utf-8''%s" % (
                        urllib.quote(upload_name.encode("utf-8")),
                    ),
                )

        # cache for at least a day.
        # XXX: we might want to turn this off for data we don't want to
        # recommend caching as it's sensitive or private - or at least
        # select private. don't bother setting Expires as all our
        # clients are smart enough to be happy with Cache-Control
        request.setHeader(
            b"Cache-Control", b"public,max-age=86400,s-maxage=86400"
        )
        if file_size is None:
            stat = os.stat(file_path)
            file_size = stat.st_size

        request.setHeader(
            b"Content-Length", b"%d" % (file_size,)
        )

        with open(file_path, "rb") as f:
            yield logcontext.make_deferred_yieldable(
                FileSender().beginFileTransfer(f, request)
            )

        finish_request(request)
    else:
        respond_404(request)
