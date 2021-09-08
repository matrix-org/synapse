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
import urllib.parse
from typing import TYPE_CHECKING, Optional

import attr

from synapse.http.client import SimpleHttpClient
from synapse.types import JsonDict
from synapse.util import json_decoder

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class OEmbedResult:
    og: JsonDict
    # Number of seconds to cache the content.
    cache_age: Optional[int]


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
                # TODO Specify max height / width.

                # Note that only the JSON format is supported, some endpoints want
                # this in the URL, others want it as an argument.
                endpoint = endpoint.replace("{format}", "json")

                args = {"url": url, "format": "json"}
                query_str = urllib.parse.urlencode(args, True)
                return f"{endpoint}?{query_str}"

        # No match.
        return None

    def parse_oembed_response(self, url: str, body: str) -> OEmbedResult:
        """
        Parse the oEmbed response into an Open Graph response.

        Args:
            url: The URL which is being previewed (not the one which was
                requested).
            body: The oEmbed response as JSON.

        Returns:
            json-encoded Open Graph data
        """

        try:
            result = json_decoder.decode(body)

            # Ensure there's a version of 1.0.
            if result.get("version") != "1.0":
                raise RuntimeError("Invalid version: %s" % (result.get("version"),))

            oembed_type = result.get("type")

            # Ensure the cache age is None or an int.
            cache_age = result.get("cache_age")
            if cache_age:
                cache_age = int(cache_age)

            # The results.
            og = {"og:title": result.get("title")}

            # If a thumbnail exists, use it. Note that dimensions will be calculated later.
            if "thumbnail_url" in result:
                og["og:image"] = result["thumbnail_url"]

            # Process each type separately.
            if oembed_type == "rich":
                calc_description_and_urls(og, result.get("html"))

            elif oembed_type == "photo":
                # If this is a photo, use the full image, not the thumbnail.
                og["og:image"] = result.get("url")

            else:
                raise RuntimeError(f"Unknown oEmbed type: {oembed_type}")

        except Exception as e:
            # Trap any exception and let the code follow as usual.
            logger.warning(f"Error parsing oEmbed metadata from {url}: {e:r}")
            og = {}
            cache_age = None

        return OEmbedResult(og, cache_age)


def calc_description_and_urls(og: JsonDict, body: str) -> None:
    """
    Calculate description for an HTML document.

    This uses lxml to convert the HTML document into plaintext. If errors
    occur during processing of the document, an empty response is returned.

    Args:
        og: The current Open Graph summary. This is updated with additional fields.
        body: The HTML document, as bytes.

    Returns:
        The summary
    """
    # If there's no body, nothing useful is going to be found.
    if not body:
        return

    from lxml import etree

    # Create an HTML parser. If this fails, log and return no metadata.
    parser = etree.HTMLParser(recover=True, encoding="utf-8")

    # Attempt to parse the body. If this fails, log and return no metadata.
    tree = etree.fromstring(body, parser)

    # The data was successfully parsed, but no tree was found.
    if tree is None:
        return

    from synapse.rest.media.v1.preview_url_resource import _calc_description

    description = _calc_description(tree)
    if description:
        og["og:description"] = description
