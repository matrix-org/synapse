# Copyright 2016 OpenMarket Ltd
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
import codecs
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
from typing import TYPE_CHECKING, Dict, Generator, Iterable, Optional, Set, Tuple, Union
from urllib import parse as urlparse

import attr

from twisted.internet.defer import Deferred
from twisted.internet.error import DNSLookupError

from synapse.api.errors import Codes, SynapseError
from synapse.http.client import SimpleHttpClient
from synapse.http.server import (
    DirectServeJsonResource,
    respond_with_json,
    respond_with_json_bytes,
)
from synapse.http.servlet import parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.rest.media.v1._base import get_filename_from_headers
from synapse.rest.media.v1.media_storage import MediaStorage
from synapse.rest.media.v1.oembed import OEmbedProvider
from synapse.types import JsonDict, UserID
from synapse.util import json_encoder
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.stringutils import random_string

from ._base import FileInfo

if TYPE_CHECKING:
    from lxml import etree

    from synapse.rest.media.v1.media_repository import MediaRepository
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

_charset_match = re.compile(
    br'<\s*meta[^>]*charset\s*=\s*"?([a-z0-9_-]+)"?', flags=re.I
)
_xml_encoding_match = re.compile(
    br'\s*<\s*\?\s*xml[^>]*encoding="([a-z0-9_-]+)"', flags=re.I
)
_content_type_match = re.compile(r'.*; *charset="?(.*?)"?(;|$)', flags=re.I)

OG_TAG_NAME_MAXLEN = 50
OG_TAG_VALUE_MAXLEN = 1000

ONE_HOUR = 60 * 60 * 1000
ONE_DAY = 24 * ONE_HOUR
IMAGE_CACHE_EXPIRY_MS = 2 * ONE_DAY


@attr.s(slots=True, frozen=True, auto_attribs=True)
class MediaInfo:
    """
    Information parsed from downloading media being previewed.
    """

    # The Content-Type header of the response.
    media_type: str
    # The length (in bytes) of the downloaded media.
    media_length: int
    # The media filename, according to the server. This is parsed from the
    # returned headers, if possible.
    download_name: Optional[str]
    # The time of the preview.
    created_ts_ms: int
    # Information from the media storage provider about where the file is stored
    # on disk.
    filesystem_id: str
    filename: str
    # The URI being previewed.
    uri: str
    # The HTTP response code.
    response_code: int
    # The timestamp (in milliseconds) of when this preview expires.
    expires: int
    # The ETag header of the response.
    etag: Optional[str]


class PreviewUrlResource(DirectServeJsonResource):
    """
    Generating URL previews is a complicated task which many potential pitfalls.

    See docs/development/url_previews.md for discussion of the design and
    algorithm followed in this module.
    """

    isLeaf = True

    def __init__(
        self,
        hs: "HomeServer",
        media_repo: "MediaRepository",
        media_storage: MediaStorage,
    ):
        super().__init__()

        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.filepaths = media_repo.filepaths
        self.max_spider_size = hs.config.media.max_spider_size
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.client = SimpleHttpClient(
            hs,
            treq_args={"browser_like_redirects": True},
            ip_whitelist=hs.config.media.url_preview_ip_range_whitelist,
            ip_blacklist=hs.config.media.url_preview_ip_range_blacklist,
            use_proxy=True,
        )
        self.media_repo = media_repo
        self.primary_base_path = media_repo.primary_base_path
        self.media_storage = media_storage

        self._oembed = OEmbedProvider(hs)

        # We run the background jobs if we're the instance specified (or no
        # instance is specified, where we assume there is only one instance
        # serving media).
        instance_running_jobs = hs.config.media.media_instance_running_background_jobs
        self._worker_run_media_background_jobs = (
            instance_running_jobs is None
            or instance_running_jobs == hs.get_instance_name()
        )

        self.url_preview_url_blacklist = hs.config.media.url_preview_url_blacklist
        self.url_preview_accept_language = hs.config.media.url_preview_accept_language

        # memory cache mapping urls to an ObservableDeferred returning
        # JSON-encoded OG metadata
        self._cache: ExpiringCache[str, ObservableDeferred] = ExpiringCache(
            cache_name="url_previews",
            clock=self.clock,
            # don't spider URLs more often than once an hour
            expiry_ms=ONE_HOUR,
        )

        if self._worker_run_media_background_jobs:
            self._cleaner_loop = self.clock.looping_call(
                self._start_expire_url_cache_data, 10 * 1000
            )

    async def _async_render_OPTIONS(self, request: SynapseRequest) -> None:
        request.setHeader(b"Allow", b"OPTIONS, GET")
        respond_with_json(request, 200, {}, send_cors=True)

    async def _async_render_GET(self, request: SynapseRequest) -> None:
        # XXX: if get_user_by_req fails, what should we do in an async render?
        requester = await self.auth.get_user_by_req(request)
        url = parse_string(request, "url", required=True)
        ts = parse_integer(request, "ts")
        if ts is None:
            ts = self.clock.time_msec()

        # XXX: we could move this into _do_preview if we wanted.
        url_tuple = urlparse.urlsplit(url)
        for entry in self.url_preview_url_blacklist:
            match = True
            for attrib in entry:
                pattern = entry[attrib]
                value = getattr(url_tuple, attrib)
                logger.debug(
                    "Matching attrib '%s' with value '%s' against pattern '%s'",
                    attrib,
                    value,
                    pattern,
                )

                if value is None:
                    match = False
                    continue

                if pattern.startswith("^"):
                    if not re.match(pattern, getattr(url_tuple, attrib)):
                        match = False
                        continue
                else:
                    if not fnmatch.fnmatch(getattr(url_tuple, attrib), pattern):
                        match = False
                        continue
            if match:
                logger.warning("URL %s blocked by url_blacklist entry %s", url, entry)
                raise SynapseError(
                    403, "URL blocked by url pattern blacklist entry", Codes.UNKNOWN
                )

        # the in-memory cache:
        # * ensures that only one request is active at a time
        # * takes load off the DB for the thundering herds
        # * also caches any failures (unlike the DB) so we don't keep
        #    requesting the same endpoint

        observable = self._cache.get(url)

        if not observable:
            download = run_in_background(self._do_preview, url, requester.user, ts)
            observable = ObservableDeferred(download, consumeErrors=True)
            self._cache[url] = observable
        else:
            logger.info("Returning cached response")

        og = await make_deferred_yieldable(observable.observe())
        respond_with_json_bytes(request, 200, og, send_cors=True)

    async def _do_preview(self, url: str, user: UserID, ts: int) -> bytes:
        """Check the db, and download the URL and build a preview

        Args:
            url: The URL to preview.
            user: The user requesting the preview.
            ts: The timestamp requested for the preview.

        Returns:
            json-encoded og data
        """
        # check the URL cache in the DB (which will also provide us with
        # historical previews, if we have any)
        cache_result = await self.store.get_url_cache(url, ts)
        if (
            cache_result
            and cache_result["expires_ts"] > ts
            and cache_result["response_code"] / 100 == 2
        ):
            # It may be stored as text in the database, not as bytes (such as
            # PostgreSQL). If so, encode it back before handing it on.
            og = cache_result["og"]
            if isinstance(og, str):
                og = og.encode("utf8")
            return og

        # If this URL can be accessed via oEmbed, use that instead.
        url_to_download = url
        oembed_url = self._oembed.get_oembed_url(url)
        if oembed_url:
            url_to_download = oembed_url

        media_info = await self._download_url(url_to_download, user)

        logger.debug("got media_info of '%s'", media_info)

        # The number of milliseconds that the response should be considered valid.
        expiration_ms = media_info.expires

        if _is_media(media_info.media_type):
            file_id = media_info.filesystem_id
            dims = await self.media_repo._generate_thumbnails(
                None, file_id, file_id, media_info.media_type, url_cache=True
            )

            og = {
                "og:description": media_info.download_name,
                "og:image": f"mxc://{self.server_name}/{media_info.filesystem_id}",
                "og:image:type": media_info.media_type,
                "matrix:image:size": media_info.media_length,
            }

            if dims:
                og["og:image:width"] = dims["width"]
                og["og:image:height"] = dims["height"]
            else:
                logger.warning("Couldn't get dims for %s" % url)

            # define our OG response for this media
        elif _is_html(media_info.media_type):
            # TODO: somehow stop a big HTML tree from exploding synapse's RAM

            with open(media_info.filename, "rb") as file:
                body = file.read()

            tree = decode_body(body, media_info.uri, media_info.media_type)
            if tree is not None:
                # Check if this HTML document points to oEmbed information and
                # defer to that.
                oembed_url = self._oembed.autodiscover_from_html(tree)
                og = {}
                if oembed_url:
                    oembed_info = await self._download_url(oembed_url, user)
                    og, expiration_ms = await self._handle_oembed_response(
                        url, oembed_info, expiration_ms
                    )

                # If there was no oEmbed URL (or oEmbed parsing failed), attempt
                # to generate the Open Graph information from the HTML.
                if not oembed_url or not og:
                    og = _calc_og(tree, media_info.uri)

                await self._precache_image_url(user, media_info, og)
            else:
                og = {}

        elif oembed_url:
            # Handle the oEmbed information.
            og, expiration_ms = await self._handle_oembed_response(
                url, media_info, expiration_ms
            )
            await self._precache_image_url(user, media_info, og)

        else:
            logger.warning("Failed to find any OG data in %s", url)
            og = {}

        # filter out any stupidly long values
        keys_to_remove = []
        for k, v in og.items():
            # values can be numeric as well as strings, hence the cast to str
            if len(k) > OG_TAG_NAME_MAXLEN or len(str(v)) > OG_TAG_VALUE_MAXLEN:
                logger.warning(
                    "Pruning overlong tag %s from OG data", k[:OG_TAG_NAME_MAXLEN]
                )
                keys_to_remove.append(k)
        for k in keys_to_remove:
            del og[k]

        logger.debug("Calculated OG for %s as %s", url, og)

        jsonog = json_encoder.encode(og)

        # Cap the amount of time to consider a response valid.
        expiration_ms = min(expiration_ms, ONE_DAY)

        # store OG in history-aware DB cache
        await self.store.store_url_cache(
            url,
            media_info.response_code,
            media_info.etag,
            media_info.created_ts_ms + expiration_ms,
            jsonog,
            media_info.filesystem_id,
            media_info.created_ts_ms,
        )

        return jsonog.encode("utf8")

    async def _download_url(self, url: str, user: UserID) -> MediaInfo:
        # TODO: we should probably honour robots.txt... except in practice
        # we're most likely being explicitly triggered by a human rather than a
        # bot, so are we really a robot?

        file_id = datetime.date.today().isoformat() + "_" + random_string(16)

        file_info = FileInfo(server_name=None, file_id=file_id, url_cache=True)

        with self.media_storage.store_into_file(file_info) as (f, fname, finish):
            try:
                logger.debug("Trying to get preview for url '%s'", url)
                length, headers, uri, code = await self.client.get_file(
                    url,
                    output_stream=f,
                    max_size=self.max_spider_size,
                    headers={"Accept-Language": self.url_preview_accept_language},
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
                    502,
                    "DNS resolution failure during URL preview generation",
                    Codes.UNKNOWN,
                )
            except Exception as e:
                # FIXME: pass through 404s and other error messages nicely
                logger.warning("Error downloading %s: %r", url, e)

                raise SynapseError(
                    500,
                    "Failed to download content: %s"
                    % (traceback.format_exception_only(sys.exc_info()[0], e),),
                    Codes.UNKNOWN,
                )
            await finish()

            if b"Content-Type" in headers:
                media_type = headers[b"Content-Type"][0].decode("ascii")
            else:
                media_type = "application/octet-stream"

            download_name = get_filename_from_headers(headers)

            # FIXME: we should calculate a proper expiration based on the
            # Cache-Control and Expire headers.  But for now, assume 1 hour.
            expires = ONE_HOUR
            etag = headers[b"ETag"][0].decode("ascii") if b"ETag" in headers else None

        try:
            time_now_ms = self.clock.time_msec()

            await self.store.store_local_media(
                media_id=file_id,
                media_type=media_type,
                time_now_ms=time_now_ms,
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

        return MediaInfo(
            media_type=media_type,
            media_length=length,
            download_name=download_name,
            created_ts_ms=time_now_ms,
            filesystem_id=file_id,
            filename=fname,
            uri=uri,
            response_code=code,
            expires=expires,
            etag=etag,
        )

    async def _precache_image_url(
        self, user: UserID, media_info: MediaInfo, og: JsonDict
    ) -> None:
        """
        Pre-cache the image (if one exists) for posterity

        Args:
            user: The user requesting the preview.
            media_info: The media being previewed.
            og: The Open Graph dictionary. This is modified with image information.
        """
        # If there's no image or it is blank, there's nothing to do.
        if "og:image" not in og or not og["og:image"]:
            return

        # FIXME: it might be cleaner to use the same flow as the main /preview_url
        # request itself and benefit from the same caching etc.  But for now we
        # just rely on the caching on the master request to speed things up.
        image_info = await self._download_url(
            _rebase_url(og["og:image"], media_info.uri), user
        )

        if _is_media(image_info.media_type):
            # TODO: make sure we don't choke on white-on-transparent images
            file_id = image_info.filesystem_id
            dims = await self.media_repo._generate_thumbnails(
                None, file_id, file_id, image_info.media_type, url_cache=True
            )
            if dims:
                og["og:image:width"] = dims["width"]
                og["og:image:height"] = dims["height"]
            else:
                logger.warning("Couldn't get dims for %s", og["og:image"])

            og["og:image"] = f"mxc://{self.server_name}/{image_info.filesystem_id}"
            og["og:image:type"] = image_info.media_type
            og["matrix:image:size"] = image_info.media_length
        else:
            del og["og:image"]

    async def _handle_oembed_response(
        self, url: str, media_info: MediaInfo, expiration_ms: int
    ) -> Tuple[JsonDict, int]:
        """
        Parse the downloaded oEmbed info.

        Args:
            url: The URL which is being previewed (not the one which was
                requested).
            media_info: The media being previewed.
            expiration_ms: The length of time, in milliseconds, the media is valid for.

        Returns:
            A tuple of:
                The Open Graph dictionary, if the oEmbed info can be parsed.
                The (possibly updated) length of time, in milliseconds, the media is valid for.
        """
        # If JSON was not returned, there's nothing to do.
        if not _is_json(media_info.media_type):
            return {}, expiration_ms

        with open(media_info.filename, "rb") as file:
            body = file.read()

        oembed_response = self._oembed.parse_oembed_response(url, body)
        open_graph_result = oembed_response.open_graph_result

        # Use the cache age from the oEmbed result, if one was given.
        if open_graph_result and oembed_response.cache_age is not None:
            expiration_ms = oembed_response.cache_age

        return open_graph_result, expiration_ms

    def _start_expire_url_cache_data(self) -> Deferred:
        return run_as_background_process(
            "expire_url_cache_data", self._expire_url_cache_data
        )

    async def _expire_url_cache_data(self) -> None:
        """Clean up expired url cache content, media and thumbnails."""

        assert self._worker_run_media_background_jobs

        now = self.clock.time_msec()

        logger.debug("Running url preview cache expiry")

        if not (await self.store.db_pool.updates.has_completed_background_updates()):
            logger.info("Still running DB updates; skipping expiry")
            return

        def try_remove_parent_dirs(dirs: Iterable[str]) -> None:
            """Attempt to remove the given chain of parent directories

            Args:
                dirs: The list of directory paths to delete, with children appearing
                    before their parents.
            """
            for dir in dirs:
                try:
                    os.rmdir(dir)
                except FileNotFoundError:
                    # Already deleted, continue with deleting the rest
                    pass
                except OSError as e:
                    # Failed, skip deleting the rest of the parent dirs
                    if e.errno != errno.ENOTEMPTY:
                        logger.warning(
                            "Failed to remove media directory: %r: %s", dir, e
                        )
                    break

        # First we delete expired url cache entries
        media_ids = await self.store.get_expired_url_cache(now)

        removed_media = []
        for media_id in media_ids:
            fname = self.filepaths.url_cache_filepath(media_id)
            try:
                os.remove(fname)
            except FileNotFoundError:
                pass  # If the path doesn't exist, meh
            except OSError as e:
                logger.warning("Failed to remove media: %r: %s", media_id, e)
                continue

            removed_media.append(media_id)

            dirs = self.filepaths.url_cache_filepath_dirs_to_delete(media_id)
            try_remove_parent_dirs(dirs)

        await self.store.delete_url_cache(removed_media)

        if removed_media:
            logger.info("Deleted %d entries from url cache", len(removed_media))
        else:
            logger.debug("No entries removed from url cache")

        # Now we delete old images associated with the url cache.
        # These may be cached for a bit on the client (i.e., they
        # may have a room open with a preview url thing open).
        # So we wait a couple of days before deleting, just in case.
        expire_before = now - IMAGE_CACHE_EXPIRY_MS
        media_ids = await self.store.get_url_cache_media_before(expire_before)

        removed_media = []
        for media_id in media_ids:
            fname = self.filepaths.url_cache_filepath(media_id)
            try:
                os.remove(fname)
            except FileNotFoundError:
                pass  # If the path doesn't exist, meh
            except OSError as e:
                logger.warning("Failed to remove media: %r: %s", media_id, e)
                continue

            dirs = self.filepaths.url_cache_filepath_dirs_to_delete(media_id)
            try_remove_parent_dirs(dirs)

            thumbnail_dir = self.filepaths.url_cache_thumbnail_directory(media_id)
            try:
                shutil.rmtree(thumbnail_dir)
            except FileNotFoundError:
                pass  # If the path doesn't exist, meh
            except OSError as e:
                logger.warning("Failed to remove media: %r: %s", media_id, e)
                continue

            removed_media.append(media_id)

            dirs = self.filepaths.url_cache_thumbnail_dirs_to_delete(media_id)
            # Note that one of the directories to be deleted has already been
            # removed by the `rmtree` above.
            try_remove_parent_dirs(dirs)

        await self.store.delete_url_cache_media(removed_media)

        if removed_media:
            logger.info("Deleted %d media from url cache", len(removed_media))
        else:
            logger.debug("No media removed from url cache")


def _normalise_encoding(encoding: str) -> Optional[str]:
    """Use the Python codec's name as the normalised entry."""
    try:
        return codecs.lookup(encoding).name
    except LookupError:
        return None


def get_html_media_encodings(body: bytes, content_type: Optional[str]) -> Iterable[str]:
    """
    Get potential encoding of the body based on the (presumably) HTML body or the content-type header.

    The precedence used for finding a character encoding is:

    1. <meta> tag with a charset declared.
    2. The XML document's character encoding attribute.
    3. The Content-Type header.
    4. Fallback to utf-8.
    5. Fallback to windows-1252.

    This roughly follows the algorithm used by BeautifulSoup's bs4.dammit.EncodingDetector.

    Args:
        body: The HTML document, as bytes.
        content_type: The Content-Type header.

    Returns:
        The character encoding of the body, as a string.
    """
    # There's no point in returning an encoding more than once.
    attempted_encodings: Set[str] = set()

    # Limit searches to the first 1kb, since it ought to be at the top.
    body_start = body[:1024]

    # Check if it has an encoding set in a meta tag.
    match = _charset_match.search(body_start)
    if match:
        encoding = _normalise_encoding(match.group(1).decode("ascii"))
        if encoding:
            attempted_encodings.add(encoding)
            yield encoding

    # TODO Support <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>

    # Check if it has an XML document with an encoding.
    match = _xml_encoding_match.match(body_start)
    if match:
        encoding = _normalise_encoding(match.group(1).decode("ascii"))
        if encoding and encoding not in attempted_encodings:
            attempted_encodings.add(encoding)
            yield encoding

    # Check the HTTP Content-Type header for a character set.
    if content_type:
        content_match = _content_type_match.match(content_type)
        if content_match:
            encoding = _normalise_encoding(content_match.group(1))
            if encoding and encoding not in attempted_encodings:
                attempted_encodings.add(encoding)
                yield encoding

    # Finally, fallback to UTF-8, then windows-1252.
    for fallback in ("utf-8", "cp1252"):
        if fallback not in attempted_encodings:
            yield fallback


def decode_body(
    body: bytes, uri: str, content_type: Optional[str] = None
) -> Optional["etree.Element"]:
    """
    This uses lxml to parse the HTML document.

    Args:
        body: The HTML document, as bytes.
        uri: The URI used to download the body.
        content_type: The Content-Type header.

    Returns:
        The parsed HTML body, or None if an error occurred during processed.
    """
    # If there's no body, nothing useful is going to be found.
    if not body:
        return None

    # The idea here is that multiple encodings are tried until one works.
    # Unfortunately the result is never used and then LXML will decode the string
    # again with the found encoding.
    for encoding in get_html_media_encodings(body, content_type):
        try:
            body.decode(encoding)
        except Exception:
            pass
        else:
            break
    else:
        logger.warning("Unable to decode HTML body for %s", uri)
        return None

    from lxml import etree

    # Create an HTML parser.
    parser = etree.HTMLParser(recover=True, encoding=encoding)

    # Attempt to parse the body. Returns None if the body was successfully
    # parsed, but no tree was found.
    return etree.fromstring(body, parser)


def _calc_og(tree: "etree.Element", media_uri: str) -> Dict[str, Optional[str]]:
    """
    Calculate metadata for an HTML document.

    This uses lxml to search the HTML document for Open Graph data.

    Args:
        tree: The parsed HTML document.
        media_url: The URI used to download the body.

    Returns:
        The Open Graph response as a dictionary.
    """

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

    og: Dict[str, Optional[str]] = {}
    for tag in tree.xpath("//*/meta[starts-with(@property, 'og:')]"):
        if "content" in tag.attrib:
            # if we've got more than 50 tags, someone is taking the piss
            if len(og) >= 50:
                logger.warning("Skipping OG for page with too many 'og:' tags")
                return {}
            og[tag.attrib["property"]] = tag.attrib["content"]

    # TODO: grab article: meta tags too, e.g.:

    # "article:publisher" : "https://www.facebook.com/thethudonline" />
    # "article:author" content="https://www.facebook.com/thethudonline" />
    # "article:tag" content="baby" />
    # "article:section" content="Breaking News" />
    # "article:published_time" content="2016-03-31T19:58:24+00:00" />
    # "article:modified_time" content="2016-04-01T18:31:53+00:00" />

    if "og:title" not in og:
        # do some basic spidering of the HTML
        title = tree.xpath("(//title)[1] | (//h1)[1] | (//h2)[1] | (//h3)[1]")
        if title and title[0].text is not None:
            og["og:title"] = title[0].text.strip()
        else:
            og["og:title"] = None

    if "og:image" not in og:
        # TODO: extract a favicon failing all else
        meta_image = tree.xpath(
            "//*/meta[translate(@itemprop, 'IMAGE', 'image')='image']/@content"
        )
        if meta_image:
            og["og:image"] = _rebase_url(meta_image[0], media_uri)
        else:
            # TODO: consider inlined CSS styles as well as width & height attribs
            images = tree.xpath("//img[@src][number(@width)>10][number(@height)>10]")
            images = sorted(
                images,
                key=lambda i: (
                    -1 * float(i.attrib["width"]) * float(i.attrib["height"])
                ),
            )
            if not images:
                images = tree.xpath("//img[@src]")
            if images:
                og["og:image"] = images[0].attrib["src"]

    if "og:description" not in og:
        meta_description = tree.xpath(
            "//*/meta"
            "[translate(@name, 'DESCRIPTION', 'description')='description']"
            "/@content"
        )
        if meta_description:
            og["og:description"] = meta_description[0]
        else:
            og["og:description"] = _calc_description(tree)
    elif og["og:description"]:
        # This must be a non-empty string at this point.
        assert isinstance(og["og:description"], str)
        og["og:description"] = summarize_paragraphs([og["og:description"]])

    # TODO: delete the url downloads to stop diskfilling,
    # as we only ever cared about its OG
    return og


def _calc_description(tree: "etree.Element") -> Optional[str]:
    """
    Calculate a text description based on an HTML document.

    Grabs any text nodes which are inside the <body/> tag, unless they are within
    an HTML5 semantic markup tag (<header/>, <nav/>, <aside/>, <footer/>), or
    if they are within a <script/> or <style/> tag.

    This is a very very very coarse approximation to a plain text render of the page.

    Args:
        tree: The parsed HTML document.

    Returns:
        The plain text description, or None if one cannot be generated.
    """
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
        etree.Comment,
    )

    # Split all the text nodes into paragraphs (by splitting on new
    # lines)
    text_nodes = (
        re.sub(r"\s+", "\n", el).strip()
        for el in _iterate_over_text(tree.find("body"), *TAGS_TO_REMOVE)
    )
    return summarize_paragraphs(text_nodes)


def _iterate_over_text(
    tree: "etree.Element", *tags_to_ignore: Iterable[Union[str, "etree.Comment"]]
) -> Generator[str, None, None]:
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

        if isinstance(el, str):
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
                elements,
            )


def _rebase_url(url: str, base: str) -> str:
    base_parts = list(urlparse.urlparse(base))
    url_parts = list(urlparse.urlparse(url))
    if not url_parts[0]:  # fix up schema
        url_parts[0] = base_parts[0] or "http"
    if not url_parts[1]:  # fix up hostname
        url_parts[1] = base_parts[1]
        if not url_parts[2].startswith("/"):
            url_parts[2] = re.sub(r"/[^/]+$", "/", base_parts[2]) + url_parts[2]
    return urlparse.urlunparse(url_parts)


def _is_media(content_type: str) -> bool:
    return content_type.lower().startswith("image/")


def _is_html(content_type: str) -> bool:
    content_type = content_type.lower()
    return content_type.startswith("text/html") or content_type.startswith(
        "application/xhtml"
    )


def _is_json(content_type: str) -> bool:
    return content_type.lower().startswith("application/json")


def summarize_paragraphs(
    text_nodes: Iterable[str], min_size: int = 200, max_size: int = 500
) -> Optional[str]:
    """
    Try to get a summary respecting first paragraph and then word boundaries.

    Args:
        text_nodes: The paragraphs to summarize.
        min_size: The minimum number of words to include.
        max_size: The maximum number of words to include.

    Returns:
        A summary of the text nodes, or None if that was not possible.
    """

    # TODO: Respect sentences?

    description = ""

    # Keep adding paragraphs until we get to the MIN_SIZE.
    for text_node in text_nodes:
        if len(description) < min_size:
            text_node = re.sub(r"[\t \r\n]+", " ", text_node)
            description += text_node + "\n\n"
        else:
            break

    description = description.strip()
    description = re.sub(r"[\t ]+", " ", description)
    description = re.sub(r"[\t \r\n]*[\r\n]+", "\n\n", description)

    # If the concatenation of paragraphs to get above MIN_SIZE
    # took us over MAX_SIZE, then we need to truncate mid paragraph
    if len(description) > max_size:
        new_desc = ""

        # This splits the paragraph into words, but keeping the
        # (preceding) whitespace intact so we can easily concat
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
        description = new_desc.strip() + "…"
    return description if description else None
