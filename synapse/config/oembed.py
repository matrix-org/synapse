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
import re
from urllib import parse as urlparse

from ._base import Config
from ._util import validate_config


class OembedConfig(Config):
    section = "oembed"

    def read_config(self, config, **kwargs):
        # FIXME: oembed_patterns needs sytests
        self.oembed_patterns = {}

        oembed_endpoints = config.get("oembed_endpoints", {})
        validate_config(
            _OEMBED_SCHEMA,
            oembed_endpoints,
            ("oembed_endpoints",),
        )
        for endpoint, globs in oembed_endpoints.items():
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
                    raise ValueError(
                        "Insecure oEmbed glob scheme: %s" % (results.scheme,)
                    )

                pattern = urlparse.urlunparse(
                    [
                        results.scheme,
                        re.escape(results.netloc).replace("\\*", "[a-zA-Z0-9_-]+"),
                    ]
                    + [re.escape(part).replace("\\*", ".+") for part in results[2:]]
                )
                self.oembed_patterns[re.compile(pattern)] = endpoint

    def generate_config_section(self, config_dir_path, server_name, **kwargs):
        return """\
        ## Oembed ##
        # A map of globs to API endpoints.

        ### Twitter.
        "https://publish.twitter.com/oembed":
          - "https://twitter.com/*/status/*"
          - "https://*.twitter.com/*/status/*"
          - "https://twitter.com/*/moments/*"
          - "https://*.twitter.com/*/moments/*"
        """


_HTTPS_URL = "^https://"
_OEMBED_SCHEMA = {
    "type": "object",
    "patternProperties": {
        _HTTPS_URL: {
            "type": "array",
            "items": {"type": "string", "pattern": _HTTPS_URL},
        }
    },
}
