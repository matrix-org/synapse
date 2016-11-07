# -*- coding: utf-8 -*-
# Copyright 2014, 2015 matrix.org
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

from ._base import Config, ConfigError
from collections import namedtuple


MISSING_NETADDR = (
    "Missing netaddr library. This is required for URL preview API."
)

MISSING_LXML = (
    """Missing lxml library. This is required for URL preview API.

    Install by running:
        pip install lxml

    Requires libxslt1-dev system package.
    """
)


ThumbnailRequirement = namedtuple(
    "ThumbnailRequirement", ["width", "height", "method", "media_type"]
)


def parse_thumbnail_requirements(thumbnail_sizes):
    """ Takes a list of dictionaries with "width", "height", and "method" keys
    and creates a map from image media types to the thumbnail size, thumbnailing
    method, and thumbnail media type to precalculate

    Args:
        thumbnail_sizes(list): List of dicts with "width", "height", and
            "method" keys
    Returns:
        Dictionary mapping from media type string to list of
        ThumbnailRequirement tuples.
    """
    requirements = {}
    for size in thumbnail_sizes:
        width = size["width"]
        height = size["height"]
        method = size["method"]
        jpeg_thumbnail = ThumbnailRequirement(width, height, method, "image/jpeg")
        png_thumbnail = ThumbnailRequirement(width, height, method, "image/png")
        requirements.setdefault("image/jpeg", []).append(jpeg_thumbnail)
        requirements.setdefault("image/gif", []).append(png_thumbnail)
        requirements.setdefault("image/png", []).append(png_thumbnail)
    return {
        media_type: tuple(thumbnails)
        for media_type, thumbnails in requirements.items()
    }


class ContentRepositoryConfig(Config):
    def read_config(self, config):
        self.max_upload_size = self.parse_size(config["max_upload_size"])
        self.max_image_pixels = self.parse_size(config["max_image_pixels"])
        self.max_spider_size = self.parse_size(config["max_spider_size"])
        self.media_store_path = self.ensure_directory(config["media_store_path"])
        self.uploads_path = self.ensure_directory(config["uploads_path"])
        self.dynamic_thumbnails = config["dynamic_thumbnails"]
        self.thumbnail_requirements = parse_thumbnail_requirements(
            config["thumbnail_sizes"]
        )
        self.url_preview_enabled = config.get("url_preview_enabled", False)
        if self.url_preview_enabled:
            try:
                import lxml
                lxml  # To stop unused lint.
            except ImportError:
                raise ConfigError(MISSING_LXML)

            try:
                from netaddr import IPSet
            except ImportError:
                raise ConfigError(MISSING_NETADDR)

            if "url_preview_ip_range_blacklist" in config:
                self.url_preview_ip_range_blacklist = IPSet(
                    config["url_preview_ip_range_blacklist"]
                )
            else:
                raise ConfigError(
                    "For security, you must specify an explicit target IP address "
                    "blacklist in url_preview_ip_range_blacklist for url previewing "
                    "to work"
                )

            self.url_preview_ip_range_whitelist = IPSet(
                config.get("url_preview_ip_range_whitelist", ())
            )

            self.url_preview_url_blacklist = config.get(
                "url_preview_url_blacklist", ()
            )

    def default_config(self, **kwargs):
        media_store = self.default_path("media_store")
        uploads_path = self.default_path("uploads")
        return """
        # Directory where uploaded images and attachments are stored.
        media_store_path: "%(media_store)s"

        # Directory where in-progress uploads are stored.
        uploads_path: "%(uploads_path)s"

        # The largest allowed upload size in bytes
        max_upload_size: "10M"

        # Maximum number of pixels that will be thumbnailed
        max_image_pixels: "32M"

        # Whether to generate new thumbnails on the fly to precisely match
        # the resolution requested by the client. If true then whenever
        # a new resolution is requested by the client the server will
        # generate a new thumbnail. If false the server will pick a thumbnail
        # from a precalculated list.
        dynamic_thumbnails: false

        # List of thumbnail to precalculate when an image is uploaded.
        thumbnail_sizes:
        - width: 32
          height: 32
          method: crop
        - width: 96
          height: 96
          method: crop
        - width: 320
          height: 240
          method: scale
        - width: 640
          height: 480
          method: scale
        - width: 800
          height: 600
          method: scale

        # Is the preview URL API enabled?  If enabled, you *must* specify
        # an explicit url_preview_ip_range_blacklist of IPs that the spider is
        # denied from accessing.
        url_preview_enabled: False

        # List of IP address CIDR ranges that the URL preview spider is denied
        # from accessing.  There are no defaults: you must explicitly
        # specify a list for URL previewing to work.  You should specify any
        # internal services in your network that you do not want synapse to try
        # to connect to, otherwise anyone in any Matrix room could cause your
        # synapse to issue arbitrary GET requests to your internal services,
        # causing serious security issues.
        #
        # url_preview_ip_range_blacklist:
        # - '127.0.0.0/8'
        # - '10.0.0.0/8'
        # - '172.16.0.0/12'
        # - '192.168.0.0/16'
        # - '100.64.0.0/10'
        # - '169.254.0.0/16'
        #
        # List of IP address CIDR ranges that the URL preview spider is allowed
        # to access even if they are specified in url_preview_ip_range_blacklist.
        # This is useful for specifying exceptions to wide-ranging blacklisted
        # target IP ranges - e.g. for enabling URL previews for a specific private
        # website only visible in your network.
        #
        # url_preview_ip_range_whitelist:
        # - '192.168.1.1'

        # Optional list of URL matches that the URL preview spider is
        # denied from accessing.  You should use url_preview_ip_range_blacklist
        # in preference to this, otherwise someone could define a public DNS
        # entry that points to a private IP address and circumvent the blacklist.
        # This is more useful if you know there is an entire shape of URL that
        # you know that will never want synapse to try to spider.
        #
        # Each list entry is a dictionary of url component attributes as returned
        # by urlparse.urlsplit as applied to the absolute form of the URL.  See
        # https://docs.python.org/2/library/urlparse.html#urlparse.urlsplit
        # The values of the dictionary are treated as an filename match pattern
        # applied to that component of URLs, unless they start with a ^ in which
        # case they are treated as a regular expression match.  If all the
        # specified component matches for a given list item succeed, the URL is
        # blacklisted.
        #
        # url_preview_url_blacklist:
        # # blacklist any URL with a username in its URI
        # - username: '*'
        #
        # # blacklist all *.google.com URLs
        # - netloc: 'google.com'
        # - netloc: '*.google.com'
        #
        # # blacklist all plain HTTP URLs
        # - scheme: 'http'
        #
        # # blacklist http(s)://www.acme.com/foo
        # - netloc: 'www.acme.com'
        #   path: '/foo'
        #
        # # blacklist any URL with a literal IPv4 address
        # - netloc: '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

        # The largest allowed URL preview spidering size in bytes
        max_spider_size: "10M"


        """ % locals()
