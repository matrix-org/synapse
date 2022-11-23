# Copyright 2014, 2015 OpenMarket Ltd
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

import logging
import os
from typing import Any, Dict, List, Tuple
from urllib.request import getproxies_environment  # type: ignore

import attr

from synapse.config.server import generate_ip_set
from synapse.types import JsonDict
from synapse.util.check_dependencies import check_requirements
from synapse.util.module_loader import load_module

from ._base import Config, ConfigError

logger = logging.getLogger(__name__)

DEFAULT_THUMBNAIL_SIZES = [
    {"width": 32, "height": 32, "method": "crop"},
    {"width": 96, "height": 96, "method": "crop"},
    {"width": 320, "height": 240, "method": "scale"},
    {"width": 640, "height": 480, "method": "scale"},
    {"width": 800, "height": 600, "method": "scale"},
]

THUMBNAIL_SIZE_YAML = """\
        #  - width: %(width)i
        #    height: %(height)i
        #    method: %(method)s
"""

# A map from the given media type to the type of thumbnail we should generate
# for it.
THUMBNAIL_SUPPORTED_MEDIA_FORMAT_MAP = {
    "image/jpeg": "jpeg",
    "image/jpg": "jpeg",
    "image/webp": "jpeg",
    # Thumbnails can only be jpeg or png. We choose png thumbnails for gif
    # because it can have transparency.
    "image/gif": "png",
    "image/png": "png",
}

HTTP_PROXY_SET_WARNING = """\
The Synapse config url_preview_ip_range_blacklist will be ignored as an HTTP(s) proxy is configured."""


@attr.s(frozen=True, slots=True, auto_attribs=True)
class ThumbnailRequirement:
    width: int
    height: int
    method: str
    media_type: str


@attr.s(frozen=True, slots=True, auto_attribs=True)
class MediaStorageProviderConfig:
    store_local: bool  # Whether to store newly uploaded local files
    store_remote: bool  # Whether to store newly downloaded remote files
    store_synchronous: bool  # Whether to wait for successful storage for local uploads


def parse_thumbnail_requirements(
    thumbnail_sizes: List[JsonDict],
) -> Dict[str, Tuple[ThumbnailRequirement, ...]]:
    """Takes a list of dictionaries with "width", "height", and "method" keys
    and creates a map from image media types to the thumbnail size, thumbnailing
    method, and thumbnail media type to precalculate

    Args:
        thumbnail_sizes: List of dicts with "width", "height", and "method" keys

    Returns:
        Dictionary mapping from media type string to list of ThumbnailRequirement.
    """
    requirements: Dict[str, List[ThumbnailRequirement]] = {}
    for size in thumbnail_sizes:
        width = size["width"]
        height = size["height"]
        method = size["method"]

        for format, thumbnail_format in THUMBNAIL_SUPPORTED_MEDIA_FORMAT_MAP.items():
            requirement = requirements.setdefault(format, [])
            if thumbnail_format == "jpeg":
                requirement.append(
                    ThumbnailRequirement(width, height, method, "image/jpeg")
                )
            elif thumbnail_format == "png":
                requirement.append(
                    ThumbnailRequirement(width, height, method, "image/png")
                )
            else:
                raise Exception(
                    "Unknown thumbnail mapping from %s to %s. This is a Synapse problem, please report!"
                    % (format, thumbnail_format)
                )
    return {
        media_type: tuple(thumbnails) for media_type, thumbnails in requirements.items()
    }


class ContentRepositoryConfig(Config):
    section = "media"

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:

        # Only enable the media repo if either the media repo is enabled or the
        # current worker app is the media repo.
        if (
            self.root.server.enable_media_repo is False
            and config.get("worker_app") != "synapse.app.media_repository"
        ):
            self.can_load_media_repo = False
            return
        else:
            self.can_load_media_repo = True

        # Whether this instance should be the one to run the background jobs to
        # e.g clean up old URL previews.
        self.media_instance_running_background_jobs = config.get(
            "media_instance_running_background_jobs",
        )

        self.max_upload_size = self.parse_size(config.get("max_upload_size", "50M"))
        self.max_image_pixels = self.parse_size(config.get("max_image_pixels", "32M"))
        self.max_spider_size = self.parse_size(config.get("max_spider_size", "10M"))

        self.media_store_path = self.ensure_directory(
            config.get("media_store_path", "media_store")
        )

        backup_media_store_path = config.get("backup_media_store_path")

        synchronous_backup_media_store = config.get(
            "synchronous_backup_media_store", False
        )

        storage_providers = config.get("media_storage_providers", [])

        if backup_media_store_path:
            if storage_providers:
                raise ConfigError(
                    "Cannot use both 'backup_media_store_path' and 'storage_providers'"
                )

            storage_providers = [
                {
                    "module": "file_system",
                    "store_local": True,
                    "store_synchronous": synchronous_backup_media_store,
                    "store_remote": True,
                    "config": {"directory": backup_media_store_path},
                }
            ]

        # This is a list of config that can be used to create the storage
        # providers. The entries are tuples of (Class, class_config,
        # MediaStorageProviderConfig), where Class is the class of the provider,
        # the class_config the config to pass to it, and
        # MediaStorageProviderConfig are options for StorageProviderWrapper.
        #
        # We don't create the storage providers here as not all workers need
        # them to be started.
        self.media_storage_providers: List[tuple] = []

        for i, provider_config in enumerate(storage_providers):
            # We special case the module "file_system" so as not to need to
            # expose FileStorageProviderBackend
            if provider_config["module"] == "file_system":
                provider_config["module"] = (
                    "synapse.rest.media.v1.storage_provider"
                    ".FileStorageProviderBackend"
                )

            provider_class, parsed_config = load_module(
                provider_config, ("media_storage_providers", "<item %i>" % i)
            )

            wrapper_config = MediaStorageProviderConfig(
                provider_config.get("store_local", False),
                provider_config.get("store_remote", False),
                provider_config.get("store_synchronous", False),
            )

            self.media_storage_providers.append(
                (provider_class, parsed_config, wrapper_config)
            )

        self.dynamic_thumbnails = config.get("dynamic_thumbnails", False)
        self.thumbnail_requirements = parse_thumbnail_requirements(
            config.get("thumbnail_sizes", DEFAULT_THUMBNAIL_SIZES)
        )
        self.url_preview_enabled = config.get("url_preview_enabled", False)
        if self.url_preview_enabled:
            check_requirements("url-preview")

            proxy_env = getproxies_environment()
            if "url_preview_ip_range_blacklist" not in config:
                if "http" not in proxy_env or "https" not in proxy_env:
                    raise ConfigError(
                        "For security, you must specify an explicit target IP address "
                        "blacklist in url_preview_ip_range_blacklist for url previewing "
                        "to work"
                    )
            else:
                if "http" in proxy_env or "https" in proxy_env:
                    logger.warning("".join(HTTP_PROXY_SET_WARNING))

            # we always blacklist '0.0.0.0' and '::', which are supposed to be
            # unroutable addresses.
            self.url_preview_ip_range_blacklist = generate_ip_set(
                config["url_preview_ip_range_blacklist"],
                ["0.0.0.0", "::"],
                config_path=("url_preview_ip_range_blacklist",),
            )

            self.url_preview_ip_range_whitelist = generate_ip_set(
                config.get("url_preview_ip_range_whitelist", ()),
                config_path=("url_preview_ip_range_whitelist",),
            )

            self.url_preview_url_blacklist = config.get("url_preview_url_blacklist", ())

            self.url_preview_accept_language = config.get(
                "url_preview_accept_language"
            ) or ["en"]

        media_retention = config.get("media_retention") or {}

        self.media_retention_local_media_lifetime_ms = None
        local_media_lifetime = media_retention.get("local_media_lifetime")
        if local_media_lifetime is not None:
            self.media_retention_local_media_lifetime_ms = self.parse_duration(
                local_media_lifetime
            )

        self.media_retention_remote_media_lifetime_ms = None
        remote_media_lifetime = media_retention.get("remote_media_lifetime")
        if remote_media_lifetime is not None:
            self.media_retention_remote_media_lifetime_ms = self.parse_duration(
                remote_media_lifetime
            )

    def generate_config_section(self, data_dir_path: str, **kwargs: Any) -> str:
        assert data_dir_path is not None
        media_store = os.path.join(data_dir_path, "media_store")
        return f"media_store_path: {media_store}"
