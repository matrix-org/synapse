# Copyright 2014-2016 OpenMarket Ltd
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

import functools
import os
import re
import string
from typing import Any, Callable, List, TypeVar, Union, cast

NEW_FORMAT_ID_RE = re.compile(r"^\d\d\d\d-\d\d-\d\d")


F = TypeVar("F", bound=Callable[..., str])


def _wrap_in_base_path(func: F) -> F:
    """Takes a function that returns a relative path and turns it into an
    absolute path based on the location of the primary media store
    """

    @functools.wraps(func)
    def _wrapped(self: "MediaFilePaths", *args: Any, **kwargs: Any) -> str:
        path = func(self, *args, **kwargs)
        return os.path.join(self.base_path, path)

    return cast(F, _wrapped)


GetPathMethod = TypeVar(
    "GetPathMethod", bound=Union[Callable[..., str], Callable[..., List[str]]]
)


def _wrap_with_jail_check(func: GetPathMethod) -> GetPathMethod:
    """Wraps a path-returning method to check that the returned path(s) do not escape
    the media store directory.

    The check is not expected to ever fail, unless `func` is missing a call to
    `_validate_path_component`, or `_validate_path_component` is buggy.

    Args:
        func: The `MediaFilePaths` method to wrap. The method may return either a single
            path, or a list of paths. Returned paths may be either absolute or relative.

    Returns:
        The method, wrapped with a check to ensure that the returned path(s) lie within
        the media store directory. Raises a `ValueError` if the check fails.
    """

    @functools.wraps(func)
    def _wrapped(
        self: "MediaFilePaths", *args: Any, **kwargs: Any
    ) -> Union[str, List[str]]:
        path_or_paths = func(self, *args, **kwargs)

        if isinstance(path_or_paths, list):
            paths_to_check = path_or_paths
        else:
            paths_to_check = [path_or_paths]

        for path in paths_to_check:
            # path may be an absolute or relative path, depending on the method being
            # wrapped. When "appending" an absolute path, `os.path.join` discards the
            # previous path, which is desired here.
            normalized_path = os.path.normpath(os.path.join(self.real_base_path, path))
            if (
                os.path.commonpath([normalized_path, self.real_base_path])
                != self.real_base_path
            ):
                raise ValueError(f"Invalid media store path: {path!r}")

        return path_or_paths

    return cast(GetPathMethod, _wrapped)


ALLOWED_CHARACTERS = set(
    string.ascii_letters
    + string.digits
    + "_-"
    + ".[]:"  # Domain names, IPv6 addresses and ports in server names
)
FORBIDDEN_NAMES = {
    "",
    os.path.curdir,  # "." for the current platform
    os.path.pardir,  # ".." for the current platform
}


def _validate_path_component(name: str) -> str:
    """Checks that the given string can be safely used as a path component

    Args:
        name: The path component to check.

    Returns:
        The path component if valid.

    Raises:
        ValueError: If `name` cannot be safely used as a path component.
    """
    if not ALLOWED_CHARACTERS.issuperset(name) or name in FORBIDDEN_NAMES:
        raise ValueError(f"Invalid path component: {name!r}")

    return name


class MediaFilePaths:
    """Describes where files are stored on disk.

    Most of the functions have a `*_rel` variant which returns a file path that
    is relative to the base media store path. This is mainly used when we want
    to write to the backup media store (when one is configured)
    """

    def __init__(self, primary_base_path: str):
        self.base_path = primary_base_path

        # The media store directory, with all symlinks resolved.
        self.real_base_path = os.path.realpath(primary_base_path)

        # Refuse to initialize if paths cannot be validated correctly for the current
        # platform.
        assert os.path.sep not in ALLOWED_CHARACTERS
        assert os.path.altsep not in ALLOWED_CHARACTERS
        # On Windows, paths have all sorts of weirdness which `_validate_path_component`
        # does not consider. In any case, the remote media store can't work correctly
        # for certain homeservers there, since ":"s aren't allowed in paths.
        assert os.name == "posix"

    @_wrap_with_jail_check
    def local_media_filepath_rel(self, media_id: str) -> str:
        return os.path.join(
            "local_content",
            _validate_path_component(media_id[0:2]),
            _validate_path_component(media_id[2:4]),
            _validate_path_component(media_id[4:]),
        )

    local_media_filepath = _wrap_in_base_path(local_media_filepath_rel)

    @_wrap_with_jail_check
    def local_media_thumbnail_rel(
        self, media_id: str, width: int, height: int, content_type: str, method: str
    ) -> str:
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (width, height, top_level_type, sub_type, method)
        return os.path.join(
            "local_thumbnails",
            _validate_path_component(media_id[0:2]),
            _validate_path_component(media_id[2:4]),
            _validate_path_component(media_id[4:]),
            _validate_path_component(file_name),
        )

    local_media_thumbnail = _wrap_in_base_path(local_media_thumbnail_rel)

    @_wrap_with_jail_check
    def local_media_thumbnail_dir(self, media_id: str) -> str:
        """
        Retrieve the local store path of thumbnails of a given media_id

        Args:
            media_id: The media ID to query.
        Returns:
            Path of local_thumbnails from media_id
        """
        return os.path.join(
            self.base_path,
            "local_thumbnails",
            _validate_path_component(media_id[0:2]),
            _validate_path_component(media_id[2:4]),
            _validate_path_component(media_id[4:]),
        )

    @_wrap_with_jail_check
    def remote_media_filepath_rel(self, server_name: str, file_id: str) -> str:
        return os.path.join(
            "remote_content",
            _validate_path_component(server_name),
            _validate_path_component(file_id[0:2]),
            _validate_path_component(file_id[2:4]),
            _validate_path_component(file_id[4:]),
        )

    remote_media_filepath = _wrap_in_base_path(remote_media_filepath_rel)

    @_wrap_with_jail_check
    def remote_media_thumbnail_rel(
        self,
        server_name: str,
        file_id: str,
        width: int,
        height: int,
        content_type: str,
        method: str,
    ) -> str:
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (width, height, top_level_type, sub_type, method)
        return os.path.join(
            "remote_thumbnail",
            _validate_path_component(server_name),
            _validate_path_component(file_id[0:2]),
            _validate_path_component(file_id[2:4]),
            _validate_path_component(file_id[4:]),
            _validate_path_component(file_name),
        )

    remote_media_thumbnail = _wrap_in_base_path(remote_media_thumbnail_rel)

    # Legacy path that was used to store thumbnails previously.
    # Should be removed after some time, when most of the thumbnails are stored
    # using the new path.
    @_wrap_with_jail_check
    def remote_media_thumbnail_rel_legacy(
        self, server_name: str, file_id: str, width: int, height: int, content_type: str
    ) -> str:
        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s" % (width, height, top_level_type, sub_type)
        return os.path.join(
            "remote_thumbnail",
            _validate_path_component(server_name),
            _validate_path_component(file_id[0:2]),
            _validate_path_component(file_id[2:4]),
            _validate_path_component(file_id[4:]),
            _validate_path_component(file_name),
        )

    def remote_media_thumbnail_dir(self, server_name: str, file_id: str) -> str:
        return os.path.join(
            self.base_path,
            "remote_thumbnail",
            _validate_path_component(server_name),
            _validate_path_component(file_id[0:2]),
            _validate_path_component(file_id[2:4]),
            _validate_path_component(file_id[4:]),
        )

    @_wrap_with_jail_check
    def url_cache_filepath_rel(self, media_id: str) -> str:
        if NEW_FORMAT_ID_RE.match(media_id):
            # Media id is of the form <DATE><RANDOM_STRING>
            # E.g.: 2017-09-28-fsdRDt24DS234dsf
            return os.path.join(
                "url_cache",
                _validate_path_component(media_id[:10]),
                _validate_path_component(media_id[11:]),
            )
        else:
            return os.path.join(
                "url_cache",
                _validate_path_component(media_id[0:2]),
                _validate_path_component(media_id[2:4]),
                _validate_path_component(media_id[4:]),
            )

    url_cache_filepath = _wrap_in_base_path(url_cache_filepath_rel)

    @_wrap_with_jail_check
    def url_cache_filepath_dirs_to_delete(self, media_id: str) -> List[str]:
        "The dirs to try and remove if we delete the media_id file"
        if NEW_FORMAT_ID_RE.match(media_id):
            return [
                os.path.join(
                    self.base_path, "url_cache", _validate_path_component(media_id[:10])
                )
            ]
        else:
            return [
                os.path.join(
                    self.base_path,
                    "url_cache",
                    _validate_path_component(media_id[0:2]),
                    _validate_path_component(media_id[2:4]),
                ),
                os.path.join(
                    self.base_path, "url_cache", _validate_path_component(media_id[0:2])
                ),
            ]

    @_wrap_with_jail_check
    def url_cache_thumbnail_rel(
        self, media_id: str, width: int, height: int, content_type: str, method: str
    ) -> str:
        # Media id is of the form <DATE><RANDOM_STRING>
        # E.g.: 2017-09-28-fsdRDt24DS234dsf

        top_level_type, sub_type = content_type.split("/")
        file_name = "%i-%i-%s-%s-%s" % (width, height, top_level_type, sub_type, method)

        if NEW_FORMAT_ID_RE.match(media_id):
            return os.path.join(
                "url_cache_thumbnails",
                _validate_path_component(media_id[:10]),
                _validate_path_component(media_id[11:]),
                _validate_path_component(file_name),
            )
        else:
            return os.path.join(
                "url_cache_thumbnails",
                _validate_path_component(media_id[0:2]),
                _validate_path_component(media_id[2:4]),
                _validate_path_component(media_id[4:]),
                _validate_path_component(file_name),
            )

    url_cache_thumbnail = _wrap_in_base_path(url_cache_thumbnail_rel)

    @_wrap_with_jail_check
    def url_cache_thumbnail_directory_rel(self, media_id: str) -> str:
        # Media id is of the form <DATE><RANDOM_STRING>
        # E.g.: 2017-09-28-fsdRDt24DS234dsf

        if NEW_FORMAT_ID_RE.match(media_id):
            return os.path.join(
                "url_cache_thumbnails",
                _validate_path_component(media_id[:10]),
                _validate_path_component(media_id[11:]),
            )
        else:
            return os.path.join(
                "url_cache_thumbnails",
                _validate_path_component(media_id[0:2]),
                _validate_path_component(media_id[2:4]),
                _validate_path_component(media_id[4:]),
            )

    url_cache_thumbnail_directory = _wrap_in_base_path(
        url_cache_thumbnail_directory_rel
    )

    @_wrap_with_jail_check
    def url_cache_thumbnail_dirs_to_delete(self, media_id: str) -> List[str]:
        "The dirs to try and remove if we delete the media_id thumbnails"
        # Media id is of the form <DATE><RANDOM_STRING>
        # E.g.: 2017-09-28-fsdRDt24DS234dsf
        if NEW_FORMAT_ID_RE.match(media_id):
            return [
                os.path.join(
                    self.base_path,
                    "url_cache_thumbnails",
                    _validate_path_component(media_id[:10]),
                    _validate_path_component(media_id[11:]),
                ),
                os.path.join(
                    self.base_path,
                    "url_cache_thumbnails",
                    _validate_path_component(media_id[:10]),
                ),
            ]
        else:
            return [
                os.path.join(
                    self.base_path,
                    "url_cache_thumbnails",
                    _validate_path_component(media_id[0:2]),
                    _validate_path_component(media_id[2:4]),
                    _validate_path_component(media_id[4:]),
                ),
                os.path.join(
                    self.base_path,
                    "url_cache_thumbnails",
                    _validate_path_component(media_id[0:2]),
                    _validate_path_component(media_id[2:4]),
                ),
                os.path.join(
                    self.base_path,
                    "url_cache_thumbnails",
                    _validate_path_component(media_id[0:2]),
                ),
            ]
