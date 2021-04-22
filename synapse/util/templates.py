# -*- coding: utf-8 -*-
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

"""Utilities for dealing with jinja2 templates"""

import time
import urllib.parse
from typing import TYPE_CHECKING, Callable, Iterable, Optional, Union

import jinja2

if TYPE_CHECKING:
    from synapse.config.homeserver import HomeServerConfig


def build_jinja_env(
    template_search_directories: Iterable[str],
    config: "HomeServerConfig",
    autoescape: Union[bool, Callable[[str], bool], None] = None,
) -> jinja2.Environment:
    """Set up a Jinja2 environment to load templates from the given search path

    The returned environment defines the following filters:
        - format_ts: formats timestamps as strings in the server's local timezone
             (XXX: why is that useful??)
        - mxc_to_http: converts mxc: uris to http URIs. Args are:
             (uri, width, height, resize_method="crop")

    and the following global variables:
        - server_name: matrix server name

    Args:
        template_search_directories: directories to search for templates

        config: homeserver config, for things like `server_name` and `public_baseurl`

        autoescape: whether template variables should be autoescaped. bool, or
           a function mapping from template name to bool. Defaults to escaping templates
           whose names end in .html, .xml or .htm.

    Returns:
        jinja environment
    """

    if autoescape is None:
        autoescape = jinja2.select_autoescape()

    loader = jinja2.FileSystemLoader(template_search_directories)
    env = jinja2.Environment(loader=loader, autoescape=autoescape)

    # Update the environment with our custom filters
    env.filters.update(
        {
            "format_ts": _format_ts_filter,
            "mxc_to_http": _create_mxc_to_http_filter(config.public_baseurl),
        }
    )

    # common variables for all templates
    env.globals.update({"server_name": config.server_name})

    return env


def _create_mxc_to_http_filter(
    public_baseurl: Optional[str],
) -> Callable[[str, int, int, str], str]:
    """Create and return a jinja2 filter that converts MXC urls to HTTP

    Args:
        public_baseurl: The public, accessible base URL of the homeserver
    """

    def mxc_to_http_filter(
        value: str, width: int, height: int, resize_method: str = "crop"
    ) -> str:
        if not public_baseurl:
            raise RuntimeError(
                "public_baseurl must be set in the homeserver config to convert MXC URLs to HTTP URLs."
            )

        if value[0:6] != "mxc://":
            return ""

        server_and_media_id = value[6:]
        fragment = None
        if "#" in server_and_media_id:
            server_and_media_id, fragment = server_and_media_id.split("#", 1)
            fragment = "#" + fragment

        params = {"width": width, "height": height, "method": resize_method}
        return "%s_matrix/media/v1/thumbnail/%s?%s%s" % (
            public_baseurl,
            server_and_media_id,
            urllib.parse.urlencode(params),
            fragment or "",
        )

    return mxc_to_http_filter


def _format_ts_filter(value: int, format: str):
    return time.strftime(format, time.localtime(value / 1000))
