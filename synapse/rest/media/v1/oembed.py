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
from typing import TYPE_CHECKING, Optional

import attr

from synapse.http.client import SimpleHttpClient

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, auto_attribs=True)
class OEmbedResult:
    # Either HTML content or URL must be provided.
    html: Optional[str]
    url: Optional[str]
    title: Optional[str]
    # Number of seconds to cache the content.
    cache_age: int


class OEmbedError(Exception):
    """An error occurred processing the oEmbed object."""


class OEmbedProvider:
    """
    A helper for accessing oEmbed content.

    It can be used to check if a URL should be accessed via oEmbed and for
    requesting/parsing oEmbed content.
    """

    def __init__(self, hs: "HomeServer", client: SimpleHttpClient):
        self._oembed_patterns = {}
        for oembed_endpoint in hs.config.oembed.oembed_patterns:
            api_endpoint = oembed_endpoint.api_endpoint

            # Only JSON is supported at the moment. This could be declared in
            # the formats field. Otherwise, if the endpoint ends in .xml assume
            # it doesn't support JSON.
            if (
                oembed_endpoint.formats is not None
                and "json" not in oembed_endpoint.formats
            ) or api_endpoint.endswith(".xml"):
                logger.info(
                    "Ignoring oEmbed endpoint due to not supporting JSON: %s",
                    api_endpoint,
                )
                continue

            # Iterate through each URL pattern and point it to the endpoint.
            for pattern in oembed_endpoint.url_patterns:
                self._oembed_patterns[pattern] = api_endpoint
        self._client = client

    def get_oembed_url(self, url: str) -> Optional[str]:
        """
        Check whether the URL should be downloaded as oEmbed content instead.

        Args:
            url: The URL to check.

        Returns:
            A URL to use instead or None if the original URL should be used.
        """
        for url_pattern, endpoint in self._oembed_patterns.items():
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

            # Note that only the JSON format is supported, some endpoints want
            # this in the URL, others want it as an argument.
            endpoint = endpoint.replace("{format}", "json")

            result = await self._client.get_json(
                endpoint,
                # TODO Specify max height / width.
                args={"url": url, "format": "json"},
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
