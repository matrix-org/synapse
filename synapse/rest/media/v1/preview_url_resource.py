# -*- coding: utf-8 -*-
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

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer
from twisted.web.resource import Resource

from synapse.api.errors import (
    SynapseError, Codes,
)
from synapse.util.stringutils import random_string
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.http.client import SpiderHttpClient
from synapse.http.server import (
    request_handler, respond_with_json_bytes
)
from synapse.util.async import ObservableDeferred
from synapse.util.stringutils import is_ascii

import os
import re
import fnmatch
import cgi
import ujson as json
import urlparse
import itertools

import logging
logger = logging.getLogger(__name__)


class PreviewUrlResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        Resource.__init__(self)

        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.version_string = hs.version_string
        self.filepaths = media_repo.filepaths
        self.max_spider_size = hs.config.max_spider_size
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.client = SpiderHttpClient(hs)
        self.media_repo = media_repo

        self.url_preview_url_blacklist = hs.config.url_preview_url_blacklist

        # simple memory cache mapping urls to OG metadata
        self.cache = ExpiringCache(
            cache_name="url_previews",
            clock=self.clock,
            # don't spider URLs more often than once an hour
            expiry_ms=60 * 60 * 1000,
        )
        self.cache.start()

        self.downloads = {}

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @request_handler()
    @defer.inlineCallbacks
    def _async_render_GET(self, request):

        # XXX: if get_user_by_req fails, what should we do in an async render?
        requester = yield self.auth.get_user_by_req(request)
        url = request.args.get("url")[0]
        if "ts" in request.args:
            ts = int(request.args.get("ts")[0])
        else:
            ts = self.clock.time_msec()

        url_tuple = urlparse.urlsplit(url)
        for entry in self.url_preview_url_blacklist:
            match = True
            for attrib in entry:
                pattern = entry[attrib]
                value = getattr(url_tuple, attrib)
                logger.debug((
                    "Matching attrib '%s' with value '%s' against"
                    " pattern '%s'"
                ) % (attrib, value, pattern))

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
                logger.warn(
                    "URL %s blocked by url_blacklist entry %s", url, entry
                )
                raise SynapseError(
                    403, "URL blocked by url pattern blacklist entry",
                    Codes.UNKNOWN
                )

        # first check the memory cache - good to handle all the clients on this
        # HS thundering away to preview the same URL at the same time.
        og = self.cache.get(url)
        if og:
            respond_with_json_bytes(request, 200, json.dumps(og), send_cors=True)
            return

        # then check the URL cache in the DB (which will also provide us with
        # historical previews, if we have any)
        cache_result = yield self.store.get_url_cache(url, ts)
        if (
            cache_result and
            cache_result["download_ts"] + cache_result["expires"] > ts and
            cache_result["response_code"] / 100 == 2
        ):
            respond_with_json_bytes(
                request, 200, cache_result["og"].encode('utf-8'),
                send_cors=True
            )
            return

        # Ensure only one download for a given URL is active at a time
        download = self.downloads.get(url)
        if download is None:
            download = self._download_url(url, requester.user)
            download = ObservableDeferred(
                download,
                consumeErrors=True
            )
            self.downloads[url] = download

            @download.addBoth
            def callback(media_info):
                del self.downloads[url]
                return media_info
        media_info = yield download.observe()

        # FIXME: we should probably update our cache now anyway, so that
        # even if the OG calculation raises, we don't keep hammering on the
        # remote server.  For now, leave it uncached to aid debugging OG
        # calculation problems

        logger.debug("got media_info of '%s'" % media_info)

        if _is_media(media_info['media_type']):
            dims = yield self.media_repo._generate_local_thumbnails(
                media_info['filesystem_id'], media_info
            )

            og = {
                "og:description": media_info['download_name'],
                "og:image": "mxc://%s/%s" % (
                    self.server_name, media_info['filesystem_id']
                ),
                "og:image:type": media_info['media_type'],
                "matrix:image:size": media_info['media_length'],
            }

            if dims:
                og["og:image:width"] = dims['width']
                og["og:image:height"] = dims['height']
            else:
                logger.warn("Couldn't get dims for %s" % url)

            # define our OG response for this media
        elif _is_html(media_info['media_type']):
            # TODO: somehow stop a big HTML tree from exploding synapse's RAM

            file = open(media_info['filename'])
            body = file.read()
            file.close()

            # clobber the encoding from the content-type, or default to utf-8
            # XXX: this overrides any <meta/> or XML charset headers in the body
            # which may pose problems, but so far seems to work okay.
            match = re.match(r'.*; *charset=(.*?)(;|$)', media_info['media_type'], re.I)
            encoding = match.group(1) if match else "utf-8"

            og = decode_and_calc_og(body, media_info['uri'], encoding)

            # pre-cache the image for posterity
            # FIXME: it might be cleaner to use the same flow as the main /preview_url
            # request itself and benefit from the same caching etc.  But for now we
            # just rely on the caching on the master request to speed things up.
            if 'og:image' in og and og['og:image']:
                image_info = yield self._download_url(
                    _rebase_url(og['og:image'], media_info['uri']), requester.user
                )

                if _is_media(image_info['media_type']):
                    # TODO: make sure we don't choke on white-on-transparent images
                    dims = yield self.media_repo._generate_local_thumbnails(
                        image_info['filesystem_id'], image_info
                    )
                    if dims:
                        og["og:image:width"] = dims['width']
                        og["og:image:height"] = dims['height']
                    else:
                        logger.warn("Couldn't get dims for %s" % og["og:image"])

                    og["og:image"] = "mxc://%s/%s" % (
                        self.server_name, image_info['filesystem_id']
                    )
                    og["og:image:type"] = image_info['media_type']
                    og["matrix:image:size"] = image_info['media_length']
                else:
                    del og["og:image"]
        else:
            logger.warn("Failed to find any OG data in %s", url)
            og = {}

        logger.debug("Calculated OG for %s as %s" % (url, og))

        # store OG in ephemeral in-memory cache
        self.cache[url] = og

        # store OG in history-aware DB cache
        yield self.store.store_url_cache(
            url,
            media_info["response_code"],
            media_info["etag"],
            media_info["expires"],
            json.dumps(og),
            media_info["filesystem_id"],
            media_info["created_ts"],
        )

        respond_with_json_bytes(request, 200, json.dumps(og), send_cors=True)

    @defer.inlineCallbacks
    def _download_url(self, url, user):
        # TODO: we should probably honour robots.txt... except in practice
        # we're most likely being explicitly triggered by a human rather than a
        # bot, so are we really a robot?

        # XXX: horrible duplication with base_resource's _download_remote_file()
        file_id = random_string(24)

        fname = self.filepaths.local_media_filepath(file_id)
        self.media_repo._makedirs(fname)

        try:
            with open(fname, "wb") as f:
                logger.debug("Trying to get url '%s'" % url)
                length, headers, uri, code = yield self.client.get_file(
                    url, output_stream=f, max_size=self.max_spider_size,
                )
                # FIXME: pass through 404s and other error messages nicely

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

        except Exception as e:
            os.remove(fname)
            raise SynapseError(
                500, ("Failed to download content: %s" % e),
                Codes.UNKNOWN
            )

        defer.returnValue({
            "media_type": media_type,
            "media_length": length,
            "download_name": download_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
            "filename": fname,
            "uri": uri,
            "response_code": code,
            # FIXME: we should calculate a proper expiration based on the
            # Cache-Control and Expire headers.  But for now, assume 1 hour.
            "expires": 60 * 60 * 1000,
            "etag": headers["ETag"][0] if "ETag" in headers else None,
        })


def decode_and_calc_og(body, media_uri, request_encoding=None):
    from lxml import etree

    try:
        parser = etree.HTMLParser(recover=True, encoding=request_encoding)
        tree = etree.fromstring(body, parser)
        og = _calc_og(tree, media_uri)
    except UnicodeDecodeError:
        # blindly try decoding the body as utf-8, which seems to fix
        # the charset mismatches on https://google.com
        parser = etree.HTMLParser(recover=True, encoding=request_encoding)
        tree = etree.fromstring(body.decode('utf-8', 'ignore'), parser)
        og = _calc_og(tree, media_uri)

    return og


def _calc_og(tree, media_uri):
    # suck our tree into lxml and define our OG response.

    # if we see any image URLs in the OG response, then spider them
    # (although the client could choose to do this by asking for previews of those
    # URLs to avoid DoSing the server)

    # "og:type"         : "video",
    # "og:url"          : "https://www.youtube.com/watch?v=LXDBoHyjmtw",
    # "og:site_name"    : "YouTube",
    # "og:video:type"   : "application/x-shockwave-flash",
    # "og:description"  : "Fun stuff happening here",
    # "og:title"        : "RemoteJam - Matrix team hack for Disrupt Europe Hackathon",
    # "og:image"        : "https://i.ytimg.com/vi/LXDBoHyjmtw/maxresdefault.jpg",
    # "og:video:url"    : "http://www.youtube.com/v/LXDBoHyjmtw?version=3&autohide=1",
    # "og:video:width"  : "1280"
    # "og:video:height" : "720",
    # "og:video:secure_url": "https://www.youtube.com/v/LXDBoHyjmtw?version=3",

    og = {}
    for tag in tree.xpath("//*/meta[starts-with(@property, 'og:')]"):
        if 'content' in tag.attrib:
            og[tag.attrib['property']] = tag.attrib['content']

    # TODO: grab article: meta tags too, e.g.:

    # "article:publisher" : "https://www.facebook.com/thethudonline" />
    # "article:author" content="https://www.facebook.com/thethudonline" />
    # "article:tag" content="baby" />
    # "article:section" content="Breaking News" />
    # "article:published_time" content="2016-03-31T19:58:24+00:00" />
    # "article:modified_time" content="2016-04-01T18:31:53+00:00" />

    if 'og:title' not in og:
        # do some basic spidering of the HTML
        title = tree.xpath("(//title)[1] | (//h1)[1] | (//h2)[1] | (//h3)[1]")
        if title and title[0].text is not None:
            og['og:title'] = title[0].text.strip()
        else:
            og['og:title'] = None

    if 'og:image' not in og:
        # TODO: extract a favicon failing all else
        meta_image = tree.xpath(
            "//*/meta[translate(@itemprop, 'IMAGE', 'image')='image']/@content"
        )
        if meta_image:
            og['og:image'] = _rebase_url(meta_image[0], media_uri)
        else:
            # TODO: consider inlined CSS styles as well as width & height attribs
            images = tree.xpath("//img[@src][number(@width)>10][number(@height)>10]")
            images = sorted(images, key=lambda i: (
                -1 * float(i.attrib['width']) * float(i.attrib['height'])
            ))
            if not images:
                images = tree.xpath("//img[@src]")
            if images:
                og['og:image'] = images[0].attrib['src']

    if 'og:description' not in og:
        meta_description = tree.xpath(
            "//*/meta"
            "[translate(@name, 'DESCRIPTION', 'description')='description']"
            "/@content")
        if meta_description:
            og['og:description'] = meta_description[0]
        else:
            # grab any text nodes which are inside the <body/> tag...
            # unless they are within an HTML5 semantic markup tag...
            # <header/>, <nav/>, <aside/>, <footer/>
            # ...or if they are within a <script/> or <style/> tag.
            # This is a very very very coarse approximation to a plain text
            # render of the page.

            # We don't just use XPATH here as that is slow on some machines.

            from lxml import etree

            TAGS_TO_REMOVE = (
                "header", "nav", "aside", "footer", "script", "style", etree.Comment
            )

            # Split all the text nodes into paragraphs (by splitting on new
            # lines)
            text_nodes = (
                re.sub(r'\s+', '\n', el).strip()
                for el in _iterate_over_text(tree.find("body"), *TAGS_TO_REMOVE)
            )
            og['og:description'] = summarize_paragraphs(text_nodes)

    # TODO: delete the url downloads to stop diskfilling,
    # as we only ever cared about its OG
    return og


def _iterate_over_text(tree, *tags_to_ignore):
    """Iterate over the tree returning text nodes in a depth first fashion,
    skipping text nodes inside certain tags.
    """
    # This is basically a stack that we extend using itertools.chain.
    # This will either consist of an element to iterate over *or* a string
    # to be returned.
    elements = iter([tree])
    while True:
        el = elements.next()
        if isinstance(el, basestring):
            yield el
        elif el is not None and el.tag not in tags_to_ignore:
            # el.text is the text before the first child, so we can immediately
            # return it if the text exists.
            if el.text:
                yield el.text

            # We add to the stack all the elements children, interspersed with
            # each child's tail text (if it exists). The tail text of a node
            # is text that comes *after* the node, so we always include it even
            # if we ignore the child node.
            elements = itertools.chain(
                itertools.chain.from_iterable(  # Basically a flatmap
                    [child, child.tail] if child.tail else [child]
                    for child in el.iterchildren()
                ),
                elements
            )


def _rebase_url(url, base):
    base = list(urlparse.urlparse(base))
    url = list(urlparse.urlparse(url))
    if not url[0]:  # fix up schema
        url[0] = base[0] or "http"
    if not url[1]:  # fix up hostname
        url[1] = base[1]
        if not url[2].startswith('/'):
            url[2] = re.sub(r'/[^/]+$', '/', base[2]) + url[2]
    return urlparse.urlunparse(url)


def _is_media(content_type):
    if content_type.lower().startswith("image/"):
        return True


def _is_html(content_type):
    content_type = content_type.lower()
    if (
        content_type.startswith("text/html") or
        content_type.startswith("application/xhtml")
    ):
        return True


def summarize_paragraphs(text_nodes, min_size=200, max_size=500):
    # Try to get a summary of between 200 and 500 words, respecting
    # first paragraph and then word boundaries.
    # TODO: Respect sentences?

    description = ''

    # Keep adding paragraphs until we get to the MIN_SIZE.
    for text_node in text_nodes:
        if len(description) < min_size:
            text_node = re.sub(r'[\t \r\n]+', ' ', text_node)
            description += text_node + '\n\n'
        else:
            break

    description = description.strip()
    description = re.sub(r'[\t ]+', ' ', description)
    description = re.sub(r'[\t \r\n]*[\r\n]+', '\n\n', description)

    # If the concatenation of paragraphs to get above MIN_SIZE
    # took us over MAX_SIZE, then we need to truncate mid paragraph
    if len(description) > max_size:
        new_desc = ""

        # This splits the paragraph into words, but keeping the
        # (preceeding) whitespace intact so we can easily concat
        # words back together.
        for match in re.finditer("\s*\S+", description):
            word = match.group()

            # Keep adding words while the total length is less than
            # MAX_SIZE.
            if len(word) + len(new_desc) < max_size:
                new_desc += word
            else:
                # At this point the next word *will* take us over
                # MAX_SIZE, but we also want to ensure that its not
                # a huge word. If it is add it anyway and we'll
                # truncate later.
                if len(new_desc) < min_size:
                    new_desc += word
                break

        # Double check that we're not over the limit
        if len(new_desc) > max_size:
            new_desc = new_desc[:max_size]

        # We always add an ellipsis because at the very least
        # we chopped mid paragraph.
        description = new_desc.strip() + u"…"
    return description if description else None
