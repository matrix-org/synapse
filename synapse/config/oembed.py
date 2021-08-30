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
import logging
import re
from os import listdir, path
from typing import Any, Dict
from urllib.parse import urlparse, urlunparse

from synapse.config._base import Config
from synapse.config._util import validate_config

logger = logging.Logger(__name__)


class OembedConfig(Config):
    section = "oembed"
    oembed_providers: Dict[str, Dict[str, Any]] = {}

    def read_config(self, config, **kwargs):
        oembed_dir = config.get("oembed_providers_dir")

        if not oembed_dir:
            return

        oembed_providers = []
        try:
            for fname in listdir(oembed_dir):
                if fname.endswith(".json"):
                    fpath = path.join(oembed_dir, fname)
                    try:
                        with open(fpath) as f:
                            oembed_providers += json.loads(f.read())
                    except Exception:
                        logger.exception(fpath)
        except Exception:
            logger.exception(oembed_dir)

        if not oembed_providers:
            return

        try:
            validate_config(
                _OEMBED_SCHEMA,
                oembed_providers,
                ("oembed_providers",),
            )
        except Exception:
            pass
            # logger.exception('oembed_providers')
            # and go on, this is not a show stopper
            # return

        for provider in oembed_providers:
            provider_url = provider["provider_url"].rstrip("/")
            for endpoint in provider["endpoints"]:
                if "schemes" not in endpoint:
                    continue

                patterns = []
                for s in endpoint["schemes"]:
                    results = urlparse(s)
                    pattern = urlunparse(
                        [
                            results.scheme,
                            re.escape(results.netloc).replace("\\*", "[a-zA-Z0-9_-]+"),
                        ]
                        + [re.escape(part).replace("\\*", ".+") for part in results[2:]]
                    )
                    patterns.append(re.compile(pattern))
                endpoint["patterns"] = patterns

            parsed = urlparse(provider_url)
            self.oembed_providers[re.sub(r"^www\.", "", parsed.netloc)] = provider

    def get_oembed_endpoint(self, url):
        """
        Check whether the URL has a oEmbed endpoint and return it.

        Args:
            url: The URL to check.

        Returns:
            oEmbed endpoint URL to use or None.
        """

        parsed = urlparse(url)
        for key, provider in self.oembed_providers.items():
            if parsed.netloc.find(key) == -1:
                continue

            for endpoint in provider["endpoints"]:
                if "discovery" in endpoint:
                    pass  # TODO

                if "patterns" not in endpoint:
                    continue

                for p in endpoint["patterns"]:
                    if p.fullmatch(url):
                        return endpoint["url"]

            return

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        ## Oembed ##

        # Providers json files directory.
        # oembed directory contains https://oembed.com/providers.json file
        # that you can place in oembed_providers_dir. Deb package does that for you.
        # Other custom providers can be added in other .json files, following the
        # same json format.
        #
        oembed_providers_dir: /etc/matrix-synapse/oembed/
        """


_STRING = {"type": "string"}
_ARRAY_OF_STRINGS = {"type": "array", "items": _STRING}
_BOOL = {"type": "boolean"}
_OEMBED_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["provider_name", "provider_url", "endpoints"],
        "properties": {
            "provider_name": _STRING,
            "provider_url": _STRING,
            "endpoints": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["url"],
                    "properties": {
                        "url": _STRING,
                        "schemes": _ARRAY_OF_STRINGS,
                        "discovery": _BOOL,
                        "formats": _ARRAY_OF_STRINGS,
                    },
                },
            },
        },
    },
}
