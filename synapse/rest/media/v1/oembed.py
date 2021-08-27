#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import logging
import re
from typing import Optional
from urllib import parse as urlparse

import attr

from synapse.http.client import SimpleHttpClient

logger = logging.getLogger(__name__)


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


class OEmbedProvider:
    def __init__(self, client: SimpleHttpClient):
        self._client = client

    def get_oembed_url(self, url: str) -> Optional[str]:
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

    async def get_oembed_content(self, endpoint: str, url: str) -> OEmbedResult:
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
            result = await self._client.get_json(
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
