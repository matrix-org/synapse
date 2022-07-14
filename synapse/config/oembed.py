# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Pattern
from urllib import parse as urlparse

import attr
import pkg_resources

from synapse.types import JsonDict

from ._base import Config, ConfigError
from ._util import validate_config


@attr.s(slots=True, frozen=True, auto_attribs=True)
class OEmbedEndpointConfig:
    # The API endpoint to fetch.
    api_endpoint: str
    # The patterns to match.
    url_patterns: List[Pattern]
    # The supported formats.
    formats: Optional[List[str]]


class OembedConfig(Config):
    """oEmbed Configuration"""

    section = "oembed"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        oembed_config: Dict[str, Any] = config.get("oembed") or {}

        # A list of patterns which will be used.
        self.oembed_patterns: List[OEmbedEndpointConfig] = list(
            self._parse_and_validate_providers(oembed_config)
        )

    def _parse_and_validate_providers(
        self, oembed_config: dict
    ) -> Iterable[OEmbedEndpointConfig]:
        """Extract and parse the oEmbed providers from the given JSON file.

        Returns a generator which yields the OidcProviderConfig objects
        """
        # Whether to use the packaged providers.json file.
        if not oembed_config.get("disable_default_providers") or False:
            with pkg_resources.resource_stream("synapse", "res/providers.json") as s:
                providers = json.load(s)

            yield from self._parse_and_validate_provider(
                providers, config_path=("oembed",)
            )

        # The JSON files which includes additional provider information.
        for i, file in enumerate(oembed_config.get("additional_providers") or []):
            # TODO Error checking.
            with open(file) as f:
                providers = json.load(f)

            yield from self._parse_and_validate_provider(
                providers,
                config_path=(
                    "oembed",
                    "additional_providers",
                    f"<item {i}>",
                ),
            )

    def _parse_and_validate_provider(
        self, providers: List[JsonDict], config_path: Iterable[str]
    ) -> Iterable[OEmbedEndpointConfig]:
        # Ensure it is the proper form.
        validate_config(
            _OEMBED_PROVIDER_SCHEMA,
            providers,
            config_path=config_path,
        )

        # Parse it and yield each result.
        for provider in providers:
            # Each provider might have multiple API endpoints, each which
            # might have multiple patterns to match.
            for endpoint in provider["endpoints"]:
                api_endpoint = endpoint["url"]

                # The API endpoint must be an HTTP(S) URL.
                results = urlparse.urlparse(api_endpoint)
                if results.scheme not in {"http", "https"}:
                    raise ConfigError(
                        f"Unsupported oEmbed scheme ({results.scheme}) for endpoint {api_endpoint}",
                        config_path,
                    )

                patterns = [
                    self._glob_to_pattern(glob, config_path)
                    for glob in endpoint["schemes"]
                ]
                yield OEmbedEndpointConfig(
                    api_endpoint, patterns, endpoint.get("formats")
                )

    def _glob_to_pattern(self, glob: str, config_path: Iterable[str]) -> Pattern:
        """
        Convert the glob into a sane regular expression to match against. The
        rules followed will be slightly different for the domain portion vs.
        the rest.

        1. The scheme must be one of HTTP / HTTPS (and have no globs).
        2. The domain can have globs, but we limit it to characters that can
           reasonably be a domain part.
           TODO: This does not attempt to handle Unicode domain names.
           TODO: The domain should not allow wildcard TLDs.
        3. Other parts allow a glob to be any one, or more, characters.
        """
        results = urlparse.urlparse(glob)

        # The scheme must be HTTP(S) (and cannot contain wildcards).
        if results.scheme not in {"http", "https"}:
            raise ConfigError(
                f"Unsupported oEmbed scheme ({results.scheme}) for pattern: {glob}",
                config_path,
            )

        pattern = urlparse.urlunparse(
            [
                results.scheme,
                re.escape(results.netloc).replace("\\*", "[a-zA-Z0-9_-]+"),
            ]
            + [re.escape(part).replace("\\*", ".+") for part in results[2:]]
        )
        return re.compile(pattern)


_OEMBED_PROVIDER_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "provider_name": {"type": "string"},
            "provider_url": {"type": "string"},
            "endpoints": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "schemes": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "url": {"type": "string"},
                        "formats": {"type": "array", "items": {"type": "string"}},
                        "discovery": {"type": "boolean"},
                    },
                    "required": ["schemes", "url"],
                },
            },
        },
        "required": ["provider_name", "provider_url", "endpoints"],
    },
}
