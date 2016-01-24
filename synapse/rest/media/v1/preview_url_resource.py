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

from twisted.web.resource import Resource
from lxml import html
from synapse.http.client import SimpleHttpClient
from synapse.http.server import respond_with_json_bytes
from simplejson import json

import logging
logger = logging.getLogger(__name__)

class PreviewUrlResource(Resource):
    isLeaf = True

    def __init__(self, hs, filepaths):
        Resource.__init__(self)
        self.client = SimpleHttpClient(hs)
        self.filepaths = filepaths
        self.max_spider_size = hs.config.max_spider_size
        self.server_name = hs.hostname
        self.clock = hs.get_clock()

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @request_handler
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        url = request.args.get("url")
        
        try:
            # TODO: keep track of whether there's an ongoing request for this preview
            # and block and return their details if there is one.

            media_info = self._download_url(url)
        except:
            os.remove(fname)
            raise

        if self._is_media(media_type):
            dims = yield self._generate_local_thumbnails(
                    media_info.filesystem_id, media_info
                  )

            og = {
                "og:description" : media_info.download_name,
                "og:image" : "mxc://%s/%s" % (self.server_name, media_info.filesystem_id),
                "og:image:type" : media_info.media_type,
                "og:image:width" : dims.width,
                "og:image:height" : dims.height,
            }

            # define our OG response for this media
        elif self._is_html(media_type):
            tree = html.parse(media_info.filename)

            # suck it up into lxml and define our OG response.
            # if we see any URLs in the OG response, then spider them
            # (although the client could choose to do this by asking for previews of those URLs to avoid DoSing the server)

            # "og:type"        : "article"
            # "og:url"         : "https://twitter.com/matrixdotorg/status/684074366691356672"
            # "og:title"       : "Matrix on Twitter"
            # "og:image"       : "https://pbs.twimg.com/profile_images/500400952029888512/yI0qtFi7_400x400.png"
            # "og:description" : "“Synapse 0.12 is out! Lots of polishing, performance &amp;amp; bugfixes: /sync API, /r0 prefix, fulltext search, 3PID invites https://t.co/5alhXLLEGP”"
            # "og:site_name"   : "Twitter"

            og = {}
            for tag in tree.xpath("//*/meta[starts-with(@property, 'og:')]"):
                og[tag.attrib['property']] = tag.attrib['content']

            # TODO: store our OG details in a cache (and expire them when stale)
            # TODO: delete the content to stop diskfilling, as we only ever cared about its OG

        respond_with_json_bytes(request, 200, json.dumps(og), send_cors=True)

    def _download_url(url):
        requester = yield self.auth.get_user_by_req(request)

        # XXX: horrible duplication with base_resource's _download_remote_file()
        file_id = random_string(24)

        fname = self.filepaths.local_media_filepath(file_id)
        self._makedirs(fname)

        try:
            with open(fname, "wb") as f:
                length, headers = yield self.client.get_file(
                    url, output_stream=f, max_size=self.max_spider_size,
                )
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
                media_id=fname,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=download_name,
                media_length=length,
                user_id=requester.user,
            )

        except:
            os.remove(fname)
            raise

        return {
            "media_type": media_type,
            "media_length": length,
            "download_name": download_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
            "filename": fname,
        }


    def _is_media(content_type):
        if content_type.lower().startswith("image/"):
            return True

    def _is_html(content_type):
        content_type = content_type.lower()
        if content_type == "text/html" or
           content_type.startswith("application/xhtml"):
            return True
