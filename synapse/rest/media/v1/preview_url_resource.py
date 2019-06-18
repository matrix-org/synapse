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

import datetime
import errno
import fnmatch
import itertools
import logging
import os
import re
import shutil
import sys
import traceback

import six
from six import string_types
from six.moves import urllib_parse as urlparse

from canonicaljson import json

from twisted.internet import defer
from twisted.internet.error import DNSLookupError
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import Codes, SynapseError
from synapse.http.client import SimpleHttpClient
from synapse.http.server import (
    respond_with_json,
    respond_with_json_bytes,
    wrap_json_request_handler,
)
from synapse.http.servlet import parse_integer, parse_string
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.rest.media.v1._base import get_filename_from_headers
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.logcontext import make_deferred_yieldable, run_in_background
from synapse.util.stringutils import random_string

from ._base import FileInfo

logger = logging.getLogger(__name__)

_charset_match = re.compile(br"<\s*meta[^>]*charset\s*=\s*([a-z0-9-]+)", flags=re.I)
_content_type_match = re.compile(r'.*; *charset="?(.*?)"?(;|$)', flags=re.I)


class PreviewUrlResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo, media_storage):
        Resource.__init__(self)

        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.filepaths = media_repo.filepaths
        self.max_spider_size = hs.config.max_spider_size
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.client = SimpleHttpClient(
            hs,
            treq_args={"browser_like_redirects": True},
            ip_whitelist=hs.config.url_preview_ip_range_whitelist,
            ip_blacklist=hs.config.url_preview_ip_range_blacklist,
        )
        self.media_repo = media_repo
        self.primary_base_path = media_repo.primary_base_path
        self.media_storage = media_storage

        self.url_preview_url_blacklist = hs.config.url_preview_url_blacklist

        # memory cache mapping urls to an ObservableDeferred returning
        # JSON-encoded OG metadata
        self._cache = ExpiringCache(
            cache_name="url_previews",
            clock=self.clock,
            # don't spider URLs more often than once an hour
            expiry_ms=60 * 60 * 1000,
        )

        self._cleaner_loop = self.clock.looping_call(
            self._start_expire_url_cache_data, 10 * 1000,
        )

    def render_OPTIONS(self, request):
        return respond_with_json(request, 200, {}, send_cors=True)

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @wrap_json_request_handler
    @defer.inlineCallbacks
    def _async_render_GET(self, request):

        # XXX: if get_user_by_req fails, what should we do in an async render?
        requester = yield self.auth.get_user_by_req(request)
        url = parse_string(request, "url")
        if b"ts" in request.args:
            ts = parse_integer(request, "ts")
        else:
            ts = self.clock.time_msec()

        # XXX: we could move this into _do_preview if we wanted.
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

        # the in-memory cache:
        # * ensures that only one request is active at a time
        # * takes load off the DB for the thundering herds
        # * also caches any failures (unlike the DB) so we don't keep
        #    requesting the same endpoint

        observable = self._cache.get(url)

        if not observable:
            download = run_in_background(
                self._do_preview,
                url, requester.user, ts,
            )
            observable = ObservableDeferred(
                download,
                consumeErrors=True
            )
            self._cache[url] = observable
        else:
            logger.info("Returning cached response")

        og = yield make_deferred_yieldable(observable.observe())
        respond_with_json_bytes(request, 200, og, send_cors=True)

    @defer.inlineCallbacks
    def _do_preview(self, url, user, ts):
        """Check the db, and download the URL and build a preview

        Args:
            url (str):
            user (str):
            ts (int):

        Returns:
            Deferred[str]: json-encoded og data
        """
        # check the URL cache in the DB (which will also provide us with
        # historical previews, if we have any)
        cache_result = yield self.store.get_url_cache(url, ts)
        if (
            cache_result and
            cache_result["expires_ts"] > ts and
            cache_result["response_code"] / 100 == 2
        ):
            # It may be stored as text in the database, not as bytes (such as
            # PostgreSQL). If so, encode it back before handing it on.
            og = cache_result["og"]
            if isinstance(og, six.text_type):
                og = og.encode('utf8')
            defer.returnValue(og)
            return

        media_info = yield self._download_url(url, user)

        logger.debug("got media_info of '%s'" % media_info)

        if _is_media(media_info['media_type']):
            file_id = media_info['filesystem_id']
            dims = yield self.media_repo._generate_thumbnails(
                None, file_id, file_id, media_info["media_type"],
                url_cache=True,
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

            with open(media_info['filename'], 'rb') as file:
                body = file.read()

            encoding = None

            # Let's try and figure out if it has an encoding set in a meta tag.
            # Limit it to the first 1kb, since it ought to be in the meta tags
            # at the top.
            match = _charset_match.search(body[:1000])

            # If we find a match, it should take precedence over the
            # Content-Type header, so set it here.
            if match:
                encoding = match.group(1).decode('ascii')

            # If we don't find a match, we'll look at the HTTP Content-Type, and
            # if that doesn't exist, we'll fall back to UTF-8.
            if not encoding:
                match = _content_type_match.match(
                    media_info['media_type']
                )
                encoding = match.group(1) if match else "utf-8"

            og = decode_and_calc_og(body, media_info['uri'], encoding)

            # pre-cache the image for posterity
            # FIXME: it might be cleaner to use the same flow as the main /preview_url
            # request itself and benefit from the same caching etc.  But for now we
            # just rely on the caching on the master request to speed things up.
            if 'og:image' in og and og['og:image']:
                image_info = yield self._download_url(
                    _rebase_url(og['og:image'], media_info['uri']), user
                )

                if _is_media(image_info['media_type']):
                    # TODO: make sure we don't choke on white-on-transparent images
                    file_id = image_info['filesystem_id']
                    dims = yield self.media_repo._generate_thumbnails(
                        None, file_id, file_id, image_info["media_type"],
                        url_cache=True,
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

        jsonog = json.dumps(og).encode('utf8')

        # store OG in history-aware DB cache
        yield self.store.store_url_cache(
            url,
            media_info["response_code"],
            media_info["etag"],
            media_info["expires"] + media_info["created_ts"],
            jsonog,
            media_info["filesystem_id"],
            media_info["created_ts"],
        )

        defer.returnValue(jsonog)

    @defer.inlineCallbacks
    def _download_url(self, url, user):
        # TODO: we should probably honour robots.txt... except in practice
        # we're most likely being explicitly triggered by a human rather than a
        # bot, so are we really a robot?

        file_id = datetime.date.today().isoformat() + '_' + random_string(16)

        file_info = FileInfo(
            server_name=None,
            file_id=file_id,
            url_cache=True,
        )

        with self.media_storage.store_into_file(file_info) as (f, fname, finish):
            try:
                logger.debug("Trying to get url '%s'" % url)
                length, headers, uri, code = yield self.client.get_file(
                    url, output_stream=f, max_size=self.max_spider_size,
                )
            except SynapseError:
                # Pass SynapseErrors through directly, so that the servlet
                # handler will return a SynapseError to the client instead of
                # blank data or a 500.
                raise
            except DNSLookupError:
                # DNS lookup returned no results
                # Note: This will also be the case if one of the resolved IP
                # addresses is blacklisted
                raise SynapseError(
                    502, "DNS resolution failure during URL preview generation",
                    Codes.UNKNOWN
                )
            except Exception as e:
                # FIXME: pass through 404s and other error messages nicely
                logger.warn("Error downloading %s: %r", url, e)

                raise SynapseError(
                    500, "Failed to download content: %s" % (
                        traceback.format_exception_only(sys.exc_info()[0], e),
                    ),
                    Codes.UNKNOWN,
                )
            yield finish()

        try:
            if b"Content-Type" in headers:
                media_type = headers[b"Content-Type"][0].decode('ascii')
            else:
                media_type = "application/octet-stream"
            time_now_ms = self.clock.time_msec()

            download_name = get_filename_from_headers(headers)

            yield self.store.store_local_media(
                media_id=file_id,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=download_name,
                media_length=length,
                user_id=user,
                url_cache=url,
            )

        except Exception as e:
            logger.error("Error handling downloaded %s: %r", url, e)
            # TODO: we really ought to delete the downloaded file in this
            # case, since we won't have recorded it in the db, and will
            # therefore not expire it.
            raise

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

    def _start_expire_url_cache_data(self):
        return run_as_background_process(
            "expire_url_cache_data", self._expire_url_cache_data,
        )

    @defer.inlineCallbacks
    def _expire_url_cache_data(self):
        """Clean up expired url cache content, media and thumbnails.
        """
        # TODO: Delete from backup media store

        now = self.clock.time_msec()

        logger.info("Running url preview cache expiry")

        if not (yield self.store.has_completed_background_updates()):
            logger.info("Still running DB updates; skipping expiry")
            return

        # First we delete expired url cache entries
        media_ids = yield self.store.get_expired_url_cache(now)

        removed_media = []
        for media_id in media_ids:
            fname = self.filepaths.url_cache_filepath(media_id)
            try:
                os.remove(fname)
            except OSError as e:
                # If the path doesn't exist, meh
                if e.errno != errno.ENOENT:
                    logger.warn("Failed to remove media: %r: %s", media_id, e)
                    continue

            removed_media.append(media_id)

            try:
                dirs = self.filepaths.url_cache_filepath_dirs_to_delete(media_id)
                for dir in dirs:
                    os.rmdir(dir)
            except Exception:
                pass

        yield self.store.delete_url_cache(removed_media)

        if removed_media:
            logger.info("Deleted %d entries from url cache", len(removed_media))

        # Now we delete old images associated with the url cache.
        # These may be cached for a bit on the client (i.e., they
        # may have a room open with a preview url thing open).
        # So we wait a couple of days before deleting, just in case.
        expire_before = now - 2 * 24 * 60 * 60 * 1000
        media_ids = yield self.store.get_url_cache_media_before(expire_before)

        removed_media = []
        for media_id in media_ids:
            fname = self.filepaths.url_cache_filepath(media_id)
            try:
                os.remove(fname)
            except OSError as e:
                # If the path doesn't exist, meh
                if e.errno != errno.ENOENT:
                    logger.warn("Failed to remove media: %r: %s", media_id, e)
                    continue

            try:
                dirs = self.filepaths.url_cache_filepath_dirs_to_delete(media_id)
                for dir in dirs:
                    os.rmdir(dir)
            except Exception:
                pass

            thumbnail_dir = self.filepaths.url_cache_thumbnail_directory(media_id)
            try:
                shutil.rmtree(thumbnail_dir)
            except OSError as e:
                # If the path doesn't exist, meh
                if e.errno != errno.ENOENT:
                    logger.warn("Failed to remove media: %r: %s", media_id, e)
                    continue

            removed_media.append(media_id)

            try:
                dirs = self.filepaths.url_cache_thumbnail_dirs_to_delete(media_id)
                for dir in dirs:
                    os.rmdir(dir)
            except Exception:
                pass

        yield self.store.delete_url_cache_media(removed_media)

        logger.info("Deleted %d media from url cache", len(removed_media))


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
                "header",
                "nav",
                "aside",
                "footer",
                "script",
                "noscript",
                "style",
                etree.Comment
            )

            # Split all the text nodes into paragraphs (by splitting on new
            # lines)
            text_nodes = (
                re.sub(r'\s+', '\n', el).strip()
                for el in _iterate_over_text(tree.find("body"), *TAGS_TO_REMOVE)
            )
            og['og:description'] = summarize_paragraphs(text_nodes)
    else:
        og['og:description'] = summarize_paragraphs([og['og:description']])

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
        el = next(elements, None)
        if el is None:
            return

        if isinstance(el, string_types):
            yield el
        elif el.tag not in tags_to_ignore:
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
        for match in re.finditer(r"\s*\S+", description):
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
