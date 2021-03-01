# -*- coding: utf-8 -*-
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
from typing import TYPE_CHECKING, Any, Dict, Generator, Iterable, Optional, Union
from urllib import parse as urlparse

import attr

from twisted.internet.error import DNSLookupError
from twisted.web.http import Request

from synapse.api.errors import Codes, SynapseError
from synapse.http.client import SimpleHttpClient
from synapse.http.server import (
    DirectServeJsonResource,
    respond_with_json,
    respond_with_json_bytes,
)
from synapse.http.servlet import parse_integer, parse_string
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.rest.media.v1._base import get_filename_from_headers
from synapse.rest.media.v1.media_storage import MediaStorage
from synapse.util import json_encoder
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.stringutils import random_string

from ._base import FileInfo

if TYPE_CHECKING:
    from lxml import etree

    from synapse.app.homeserver import HomeServer
    from synapse.rest.media.v1.media_repository import MediaRepository

logger = logging.getLogger(__name__)

_charset_match = re.compile(br'<\s*meta[^>]*charset\s*=\s*"?([a-z0-9-]+)"?', flags=re.I)
_xml_encoding_match = re.compile(
    br'\s*<\s*\?\s*xml[^>]*encoding="([a-z0-9-]+)"', flags=re.I
)
_content_type_match = re.compile(r'.*; *charset="?(.*?)"?(;|$)', flags=re.I)

OG_TAG_NAME_MAXLEN = 50
OG_TAG_VALUE_MAXLEN = 1000

ONE_HOUR = 60 * 60 * 1000

# A map of globs to API endpoints.
_oembed_globs = {
    # Twitter.
    "https://publish.twitter.com/oembed": [
        "https://twitter.com/*/status/*",
        "https://*.twitter.com/*/status/*",
        "https://twitter.com/*/moments/*",
        "https://*.twitter.com/*/moments/*",
        # Include the HTTP versions too.
        "http://twitter.com/*/status/*",
        "http://*.twitter.com/*/status/*",
        "http://twitter.com/*/moments/*",
        "http://*.twitter.com/*/moments/*",
    ],
}
# Convert the globs to regular expressions.
_oembed_patterns = {}
for endpoint, globs in _oembed_globs.items():
    for glob in globs:
        # Convert the glob into a sane regular expression to match against. The
        # rules followed will be slightly different for the domain portion vs.
        # the rest.
        #
        # 1. The scheme must be one of HTTP / HTTPS (and have no globs).
        # 2. The domain can have globs, but we limit it to characters that can
        #    reasonably be a domain part.
        #    TODO: This does not attempt to handle Unicode domain names.
        # 3. Other parts allow a glob to be any one, or more, characters.
        results = urlparse.urlparse(glob)

        # Ensure the scheme does not have wildcards (and is a sane scheme).
        if results.scheme not in {"http", "https"}:
            raise ValueError("Insecure oEmbed glob scheme: %s" % (results.scheme,))

        pattern = urlparse.urlunparse(
            [
                results.scheme,
                re.escape(results.netloc).replace("\\*", "[a-zA-Z0-9_-]+"),
            ]
            + [re.escape(part).replace("\\*", ".+") for part in results[2:]]
        )
        _oembed_patterns[re.compile(pattern)] = endpoint


@attr.s(slots=True)
class OEmbedResult:
    # Either HTML content or URL must be provided.
    html = attr.ib(type=Optional[str])
    url = attr.ib(type=Optional[str])
    title = attr.ib(type=Optional[str])
    # Number of seconds to cache the content.
    cache_age = attr.ib(type=int)


class OEmbedError(Exception):
    """An error occurred processing the oEmbed object."""


class PreviewUrlResource(DirectServeJsonResource):
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
        self.max_spider_size = hs.config.max_spider_size
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.client = SimpleHttpClient(
            hs,
            treq_args={"browser_like_redirects": True},
            ip_whitelist=hs.config.url_preview_ip_range_whitelist,
            ip_blacklist=hs.config.url_preview_ip_range_blacklist,
            http_proxy=os.getenvb(b"http_proxy"),
            https_proxy=os.getenvb(b"HTTPS_PROXY"),
        )
        self.media_repo = media_repo
        self.primary_base_path = media_repo.primary_base_path
        self.media_storage = media_storage

        # We run the background jobs if we're the instance specified (or no
        # instance is specified, where we assume there is only one instance
        # serving media).
        instance_running_jobs = hs.config.media.media_instance_running_background_jobs
        self._worker_run_media_background_jobs = (
            instance_running_jobs is None
            or instance_running_jobs == hs.get_instance_name()
        )

        self.url_preview_url_blacklist = hs.config.url_preview_url_blacklist
        self.url_preview_accept_language = hs.config.url_preview_accept_language

        # memory cache mapping urls to an ObservableDeferred returning
        # JSON-encoded OG metadata
        self._cache = ExpiringCache(
            cache_name="url_previews",
            clock=self.clock,
            # don't spider URLs more often than once an hour
            expiry_ms=ONE_HOUR,
        )

        if self._worker_run_media_background_jobs:
            self._cleaner_loop = self.clock.looping_call(
                self._start_expire_url_cache_data, 10 * 1000
            )

    async def _async_render_OPTIONS(self, request: Request) -> None:
        request.setHeader(b"Allow", b"OPTIONS, GET")
        respond_with_json(request, 200, {}, send_cors=True)

    async def _async_render_GET(self, request: Request) -> None:

        # XXX: if get_user_by_req fails, what should we do in an async render?
        requester = await self.auth.get_user_by_req(request)
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

    async def _do_preview(self, url: str, user: str, ts: int) -> bytes:
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

        media_info = await self._download_url(url, user)

        logger.debug("got media_info of '%s'", media_info)

        if _is_media(media_info["media_type"]):
            file_id = media_info["filesystem_id"]
            dims = await self.media_repo._generate_thumbnails(
                None, file_id, file_id, media_info["media_type"], url_cache=True
            )

            og = {
                "og:description": media_info["download_name"],
                "og:image": "mxc://%s/%s"
                % (self.server_name, media_info["filesystem_id"]),
                "og:image:type": media_info["media_type"],
                "matrix:image:size": media_info["media_length"],
            }

            if dims:
                og["og:image:width"] = dims["width"]
                og["og:image:height"] = dims["height"]
            else:
                logger.warning("Couldn't get dims for %s" % url)

            # define our OG response for this media
        elif _is_html(media_info["media_type"]):
            # TODO: somehow stop a big HTML tree from exploding synapse's RAM

            with open(media_info["filename"], "rb") as file:
                body = file.read()

            encoding = get_html_media_encoding(body, media_info["media_type"])
            og = decode_and_calc_og(body, media_info["uri"], encoding)

            # pre-cache the image for posterity
            # FIXME: it might be cleaner to use the same flow as the main /preview_url
            # request itself and benefit from the same caching etc.  But for now we
            # just rely on the caching on the master request to speed things up.
            if "og:image" in og and og["og:image"]:
                image_info = await self._download_url(
                    _rebase_url(og["og:image"], media_info["uri"]), user
                )

                if _is_media(image_info["media_type"]):
                    # TODO: make sure we don't choke on white-on-transparent images
                    file_id = image_info["filesystem_id"]
                    dims = await self.media_repo._generate_thumbnails(
                        None, file_id, file_id, image_info["media_type"], url_cache=True
                    )
                    if dims:
                        og["og:image:width"] = dims["width"]
                        og["og:image:height"] = dims["height"]
                    else:
                        logger.warning("Couldn't get dims for %s", og["og:image"])

                    og["og:image"] = "mxc://%s/%s" % (
                        self.server_name,
                        image_info["filesystem_id"],
                    )
                    og["og:image:type"] = image_info["media_type"]
                    og["matrix:image:size"] = image_info["media_length"]
                else:
                    del og["og:image"]
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

        # store OG in history-aware DB cache
        await self.store.store_url_cache(
            url,
            media_info["response_code"],
            media_info["etag"],
            media_info["expires"] + media_info["created_ts"],
            jsonog,
            media_info["filesystem_id"],
            media_info["created_ts"],
        )

        return jsonog.encode("utf8")

    def _get_oembed_url(self, url: str) -> Optional[str]:
        """
        Check whether the URL should be downloaded as oEmbed content instead.

        Args:
            url: The URL to check.

        Returns:
            A URL to use instead or None if the original URL should be used.
        """
        for url_pattern, endpoint in _oembed_patterns.items():
            if url_pattern.fullmatch(url):
                return endpoint

        # No match.
        return None

    async def _get_oembed_content(self, endpoint: str, url: str) -> OEmbedResult:
        """
        Request content from an oEmbed endpoint.

        Args:
            endpoint: The oEmbed API endpoint.
            url: The URL to pass to the API.

        Returns:
            An object representing the metadata returned.

        Raises:
            OEmbedError if fetching or parsing of the oEmbed information fails.
        """
        try:
            logger.debug("Trying to get oEmbed content for url '%s'", url)
            result = await self.client.get_json(
                endpoint,
                # TODO Specify max height / width.
                # Note that only the JSON format is supported.
                args={"url": url},
            )

            # Ensure there's a version of 1.0.
            if result.get("version") != "1.0":
                raise OEmbedError("Invalid version: %s" % (result.get("version"),))

            oembed_type = result.get("type")

            # Ensure the cache age is None or an int.
            cache_age = result.get("cache_age")
            if cache_age:
                cache_age = int(cache_age)

            oembed_result = OEmbedResult(None, None, result.get("title"), cache_age)

            # HTML content.
            if oembed_type == "rich":
                oembed_result.html = result.get("html")
                return oembed_result

            if oembed_type == "photo":
                oembed_result.url = result.get("url")
                return oembed_result

            # TODO Handle link and video types.

            if "thumbnail_url" in result:
                oembed_result.url = result.get("thumbnail_url")
                return oembed_result

            raise OEmbedError("Incompatible oEmbed information.")

        except OEmbedError as e:
            # Trap OEmbedErrors first so we can directly re-raise them.
            logger.warning("Error parsing oEmbed metadata from %s: %r", url, e)
            raise

        except Exception as e:
            # Trap any exception and let the code follow as usual.
            # FIXME: pass through 404s and other error messages nicely
            logger.warning("Error downloading oEmbed metadata from %s: %r", url, e)
            raise OEmbedError() from e

    async def _download_url(self, url: str, user: str) -> Dict[str, Any]:
        # TODO: we should probably honour robots.txt... except in practice
        # we're most likely being explicitly triggered by a human rather than a
        # bot, so are we really a robot?

        file_id = datetime.date.today().isoformat() + "_" + random_string(16)

        file_info = FileInfo(server_name=None, file_id=file_id, url_cache=True)

        # If this URL can be accessed via oEmbed, use that instead.
        url_to_download = url  # type: Optional[str]
        oembed_url = self._get_oembed_url(url)
        if oembed_url:
            # The result might be a new URL to download, or it might be HTML content.
            try:
                oembed_result = await self._get_oembed_content(oembed_url, url)
                if oembed_result.url:
                    url_to_download = oembed_result.url
                elif oembed_result.html:
                    url_to_download = None
            except OEmbedError:
                # If an error occurs, try doing a normal preview.
                pass

        if url_to_download:
            with self.media_storage.store_into_file(file_info) as (f, fname, finish):
                try:
                    logger.debug("Trying to get preview for url '%s'", url_to_download)
                    length, headers, uri, code = await self.client.get_file(
                        url_to_download,
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
                    logger.warning("Error downloading %s: %r", url_to_download, e)

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
                etag = (
                    headers[b"ETag"][0].decode("ascii") if b"ETag" in headers else None
                )
        else:
            # we can only get here if we did an oembed request and have an oembed_result.html
            assert oembed_result.html is not None
            assert oembed_url is not None

            html_bytes = oembed_result.html.encode("utf-8")
            with self.media_storage.store_into_file(file_info) as (f, fname, finish):
                f.write(html_bytes)
                await finish()

            media_type = "text/html"
            download_name = oembed_result.title
            length = len(html_bytes)
            # If a specific cache age was not given, assume 1 hour.
            expires = oembed_result.cache_age or ONE_HOUR
            uri = oembed_url
            code = 200
            etag = None

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

        return {
            "media_type": media_type,
            "media_length": length,
            "download_name": download_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
            "filename": fname,
            "uri": uri,
            "response_code": code,
            "expires": expires,
            "etag": etag,
        }

    def _start_expire_url_cache_data(self):
        return run_as_background_process(
            "expire_url_cache_data", self._expire_url_cache_data
        )

    async def _expire_url_cache_data(self) -> None:
        """Clean up expired url cache content, media and thumbnails."""
        # TODO: Delete from backup media store

        assert self._worker_run_media_background_jobs

        now = self.clock.time_msec()

        logger.debug("Running url preview cache expiry")

        if not (await self.store.db_pool.updates.has_completed_background_updates()):
            logger.info("Still running DB updates; skipping expiry")
            return

        # First we delete expired url cache entries
        media_ids = await self.store.get_expired_url_cache(now)

        removed_media = []
        for media_id in media_ids:
            fname = self.filepaths.url_cache_filepath(media_id)
            try:
                os.remove(fname)
            except OSError as e:
                # If the path doesn't exist, meh
                if e.errno != errno.ENOENT:
                    logger.warning("Failed to remove media: %r: %s", media_id, e)
                    continue

            removed_media.append(media_id)

            try:
                dirs = self.filepaths.url_cache_filepath_dirs_to_delete(media_id)
                for dir in dirs:
                    os.rmdir(dir)
            except Exception:
                pass

        await self.store.delete_url_cache(removed_media)

        if removed_media:
            logger.info("Deleted %d entries from url cache", len(removed_media))
        else:
            logger.debug("No entries removed from url cache")

        # Now we delete old images associated with the url cache.
        # These may be cached for a bit on the client (i.e., they
        # may have a room open with a preview url thing open).
        # So we wait a couple of days before deleting, just in case.
        expire_before = now - 2 * 24 * ONE_HOUR
        media_ids = await self.store.get_url_cache_media_before(expire_before)

        removed_media = []
        for media_id in media_ids:
            fname = self.filepaths.url_cache_filepath(media_id)
            try:
                os.remove(fname)
            except OSError as e:
                # If the path doesn't exist, meh
                if e.errno != errno.ENOENT:
                    logger.warning("Failed to remove media: %r: %s", media_id, e)
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
                    logger.warning("Failed to remove media: %r: %s", media_id, e)
                    continue

            removed_media.append(media_id)

            try:
                dirs = self.filepaths.url_cache_thumbnail_dirs_to_delete(media_id)
                for dir in dirs:
                    os.rmdir(dir)
            except Exception:
                pass

        await self.store.delete_url_cache_media(removed_media)

        if removed_media:
            logger.info("Deleted %d media from url cache", len(removed_media))
        else:
            logger.debug("No media removed from url cache")


def get_html_media_encoding(body: bytes, content_type: str) -> str:
    """
    Get the encoding of the body based on the (presumably) HTML body or media_type.

    The precedence used for finding a character encoding is:

    1. meta tag with a charset declared.
    2. The XML document's character encoding attribute.
    3. The Content-Type header.
    4. Fallback to UTF-8.

    Args:
        body: The HTML document, as bytes.
        content_type: The Content-Type header.

    Returns:
        The character encoding of the body, as a string.
    """
    # Limit searches to the first 1kb, since it ought to be at the top.
    body_start = body[:1024]

    # Let's try and figure out if it has an encoding set in a meta tag.
    match = _charset_match.search(body_start)
    if match:
        return match.group(1).decode("ascii")

    # TODO Support <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>

    # If we didn't find a match, see if it an XML document with an encoding.
    match = _xml_encoding_match.match(body_start)
    if match:
        return match.group(1).decode("ascii")

    # If we don't find a match, we'll look at the HTTP Content-Type, and
    # if that doesn't exist, we'll fall back to UTF-8.
    content_match = _content_type_match.match(content_type)
    if content_match:
        return content_match.group(1)

    return "utf-8"


def decode_and_calc_og(
    body: bytes, media_uri: str, request_encoding: Optional[str] = None
) -> Dict[str, Optional[str]]:
    """
    Calculate metadata for an HTML document.

    This uses lxml to parse the HTML document into the OG response. If errors
    occur during processing of the document, an empty response is returned.

    Args:
        body: The HTML document, as bytes.
        media_url: The URI used to download the body.
        request_encoding: The character encoding of the body, as a string.

    Returns:
        The OG response as a dictionary.
    """
    # If there's no body, nothing useful is going to be found.
    if not body:
        return {}

    from lxml import etree

    # Create an HTML parser. If this fails, log and return no metadata.
    try:
        parser = etree.HTMLParser(recover=True, encoding=request_encoding)
    except LookupError:
        # blindly consider the encoding as utf-8.
        parser = etree.HTMLParser(recover=True, encoding="utf-8")
    except Exception as e:
        logger.warning("Unable to create HTML parser: %s" % (e,))
        return {}

    def _attempt_calc_og(body_attempt: Union[bytes, str]) -> Dict[str, Optional[str]]:
        # Attempt to parse the body. If this fails, log and return no metadata.
        tree = etree.fromstring(body_attempt, parser)

        # The data was successfully parsed, but no tree was found.
        if tree is None:
            return {}

        return _calc_og(tree, media_uri)

    # Attempt to parse the body. If this fails, log and return no metadata.
    try:
        return _attempt_calc_og(body)
    except UnicodeDecodeError:
        # blindly try decoding the body as utf-8, which seems to fix
        # the charset mismatches on https://google.com
        return _attempt_calc_og(body.decode("utf-8", "ignore"))


def _calc_og(tree: "etree.Element", media_uri: str) -> Dict[str, Optional[str]]:
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

    og = {}  # type: Dict[str, Optional[str]]
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
                etree.Comment,
            )

            # Split all the text nodes into paragraphs (by splitting on new
            # lines)
            text_nodes = (
                re.sub(r"\s+", "\n", el).strip()
                for el in _iterate_over_text(tree.find("body"), *TAGS_TO_REMOVE)
            )
            og["og:description"] = summarize_paragraphs(text_nodes)
    elif og["og:description"]:
        # This must be a non-empty string at this point.
        assert isinstance(og["og:description"], str)
        og["og:description"] = summarize_paragraphs([og["og:description"]])

    # TODO: delete the url downloads to stop diskfilling,
    # as we only ever cared about its OG
    return og


def _iterate_over_text(
    tree, *tags_to_ignore: Iterable[Union[str, "etree.Comment"]]
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


def summarize_paragraphs(
    text_nodes: Iterable[str], min_size: int = 200, max_size: int = 500
) -> Optional[str]:
    # Try to get a summary of between 200 and 500 words, respecting
    # first paragraph and then word boundaries.
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
        description = new_desc.strip() + "…"
    return description if description else None
