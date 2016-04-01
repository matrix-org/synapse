# Copyright 2016 OpenMarket Ltd
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

from .base_resource import BaseMediaResource
from synapse.api.errors import Codes
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer
from lxml import html
from urlparse import urlparse, urlunparse
from synapse.util.stringutils import random_string
from synapse.http.client import SpiderHttpClient
from synapse.http.server import request_handler, respond_with_json, respond_with_json_bytes

import os
import re
import ujson as json

import logging
logger = logging.getLogger(__name__)

class PreviewUrlResource(BaseMediaResource):
    isLeaf = True

    def __init__(self, hs, filepaths):
        BaseMediaResource.__init__(self, hs, filepaths)
        self.client = SpiderHttpClient(hs)

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @request_handler
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        
        try:
            # XXX: if get_user_by_req fails, what should we do in an async render?
            requester = yield self.auth.get_user_by_req(request)
            url = request.args.get("url")[0]

            # TODO: keep track of whether there's an ongoing request for this preview
            # and block and return their details if there is one.

            media_info = yield self._download_url(url, requester.user)

            logger.debug("got media_info of '%s'" % media_info)

            if self._is_media(media_info['media_type']):
                dims = yield self._generate_local_thumbnails(
                        media_info['filesystem_id'], media_info
                      )

                og = {
                    "og:description" : media_info['download_name'],
                    "og:image" : "mxc://%s/%s" % (self.server_name, media_info['filesystem_id']),
                    "og:image:type" : media_info['media_type'],
                    "og:image:width" : dims['width'],
                    "og:image:height" : dims['height'],
                }

                # define our OG response for this media
            elif self._is_html(media_info['media_type']):
                # TODO: somehow stop a big HTML tree from exploding synapse's RAM

                def _calc_og():
                    # suck it up into lxml and define our OG response.
                    # if we see any URLs in the OG response, then spider them
                    # (although the client could choose to do this by asking for previews of those URLs to avoid DoSing the server)

                    # "og:type"        : "article"
                    # "og:url"         : "https://twitter.com/matrixdotorg/status/684074366691356672"
                    # "og:title"       : "Matrix on Twitter"
                    # "og:image"       : "https://pbs.twimg.com/profile_images/500400952029888512/yI0qtFi7_400x400.png"
                    # "og:description" : "Synapse 0.12 is out! Lots of polishing, performance &amp;amp; bugfixes: /sync API, /r0 prefix, fulltext search, 3PID invites https://t.co/5alhXLLEGP"
                    # "og:site_name"   : "Twitter"
                    
                    # or:

                    # "og:type"         : "video",
                    # "og:url"          : "https://www.youtube.com/watch?v=LXDBoHyjmtw",
                    # "og:site_name"    : "YouTube",
                    # "og:video:type"   : "application/x-shockwave-flash",
                    # "og:description"  : " ",
                    # "og:title"        : "RemoteJam - Matrix team hack for Disrupt Europe Hackathon",
                    # "og:image"        : "https://i.ytimg.com/vi/LXDBoHyjmtw/maxresdefault.jpg",
                    # "og:video:url"    : "http://www.youtube.com/v/LXDBoHyjmtw?version=3&autohide=1",
                    # "og:video:width"  : "1280"
                    # "og:video:height" : "720",
                    # "og:video:secure_url": "https://www.youtube.com/v/LXDBoHyjmtw?version=3&autohide=1",

                    og = {}
                    for tag in tree.xpath("//*/meta[starts-with(@property, 'og:')]"):
                        og[tag.attrib['property']] = tag.attrib['content']

                    if 'og:title' not in og:
                        # do some basic spidering of the HTML
                        title = tree.xpath("(//title)[1] | (//h1)[1] | (//h2)[1] | (//h3)[1]")
                        og['og:title'] = title[0].text if title else None


                    if 'og:image' not in og:
                        meta_image = tree.xpath("//*/meta[@itemprop='image']/@content");
                        if meta_image:
                            og['og:image'] = self._rebase_url(meta_image[0], media_info['uri'])
                        else:
                            images = [ i for i in tree.xpath("//img") if 'src' in i.attrib ]
                            big_images = [ i for i in images if (
                                'width' in i.attrib and 'height' in i.attrib and
                                i.attrib['width'] > 64 and i.attrib['height'] > 64
                            )]
                            big_images = big_images.sort(key=lambda i: (-1 * int(i.attrib['width']) * int(i.attrib['height'])))
                            images = big_images if big_images else images

                            if images:
                                og['og:image'] = self._rebase_url(images[0].attrib['src'], media_info['uri'])

                    if 'og:description' not in og:
                        meta_description = tree.xpath("//*/meta[@name='description']/@content");
                        if meta_description:
                            og['og:description'] = meta_description[0]
                        else:
                            text_nodes = tree.xpath("//h1/text() | //h2/text() | //h3/text() | //p/text() | //div/text() | //span/text() | //a/text()")
                            # text_nodes = tree.xpath("//h1/text() | //h2/text() | //h3/text() | //p/text() | //div/text()")
                            text = ''
                            for text_node in text_nodes:
                                if len(text) < 500:
                                    text += text_node + ' '
                                else:
                                    break
                            text = re.sub(r'[\t ]+', ' ', text)
                            text = re.sub(r'[\t \r\n]*[\r\n]+', '\n', text)
                            text = text.strip()[:500]
                            og['og:description'] = text if text else None

                    # TODO: extract a favicon?
                    # TODO: turn any OG media URLs into mxc URLs to capture and thumbnail them too
                    # TODO: store our OG details in a cache (and expire them when stale)
                    # TODO: delete the content to stop diskfilling, as we only ever cared about its OG
                    return og

                try:
                    tree = html.parse(media_info['filename'])
                    og = _calc_og()
                except UnicodeDecodeError:
                    # XXX: evil evil bodge
                    file = open(media_info['filename'])
                    body = file.read()
                    file.close()
                    tree = html.fromstring(body.decode('utf-8','ignore'))
                    og = _calc_og()

            else:
                logger.warn("Failed to find any OG data in %s", url)
                og = {}

            logger.warn(og)

            respond_with_json_bytes(request, 200, json.dumps(og), send_cors=True)
        except:
            # XXX: if we don't explicitly respond here, the request never returns.
            # isn't this what server.py's wrapper is meant to be doing for us?
            respond_with_json(
                request,
                500,
                {
                    "error": "Internal server error",
                    "errcode": Codes.UNKNOWN,
                },
                send_cors=True
            )
            raise

    def _rebase_url(self, url, base):
        base = list(urlparse(base))
        url = list(urlparse(url))
        if not url[0] and not url[1]:
            url[0] = base[0]
            url[1] = base[1]
            if not url[2].startswith('/'):
                url[2] = re.sub(r'/[^/]+$', '/', base[2]) + url[2]
        return urlunparse(url)

    @defer.inlineCallbacks
    def _download_url(self, url, user):
        # TODO: we should probably honour robots.txt... except in practice
        # we're most likely being explicitly triggered by a human rather than a
        # bot, so are we really a robot?

        # XXX: horrible duplication with base_resource's _download_remote_file()
        file_id = random_string(24)

        fname = self.filepaths.local_media_filepath(file_id)
        self._makedirs(fname)

        try:
            with open(fname, "wb") as f:
                logger.debug("Trying to get url '%s'" % url)
                length, headers, uri = yield self.client.get_file(
                    url, output_stream=f, max_size=self.max_spider_size,
                )
                # FIXME: handle 404s sanely - don't spider an error page
            media_type = headers["Content-Type"][0]
            time_now_ms = self.clock.time_msec()

            content_disposition = headers.get("Content-Disposition", None)
            if content_disposition:
                _, params = cgi.parse_header(content_disposition[0],)
                download_name = None

                # First check if there is a valid UTF-8 filename
                download_name_utf8 = params.get("filename*", None)
                if download_name_utf8:
                    if download_name_utf8.lower().startswith("utf-8''"):
                        download_name = download_name_utf8[7:]

                # If there isn't check for an ascii name.
                if not download_name:
                    download_name_ascii = params.get("filename", None)
                    if download_name_ascii and is_ascii(download_name_ascii):
                        download_name = download_name_ascii

                if download_name:
                    download_name = urlparse.unquote(download_name)
                    try:
                        download_name = download_name.decode("utf-8")
                    except UnicodeDecodeError:
                        download_name = None
            else:
                download_name = None

            yield self.store.store_local_media(
                media_id=file_id,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=download_name,
                media_length=length,
                user_id=user,
            )

        except:
            os.remove(fname)
            raise

        defer.returnValue({
            "media_type": media_type,
            "media_length": length,
            "download_name": download_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
            "filename": fname,
            "uri": uri,
        })

    def _is_media(self, content_type):
        if content_type.lower().startswith("image/"):
            return True

    def _is_html(self, content_type):
        content_type = content_type.lower()
        if (content_type.startswith("text/html") or
            content_type.startswith("application/xhtml")):
            return True
