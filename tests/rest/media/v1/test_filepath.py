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
import inspect
from typing import Iterable

from synapse.rest.media.v1.filepath import MediaFilePaths

from tests import unittest


class MediaFilePathsTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.filepaths = MediaFilePaths("/media_store")

    def test_local_media_filepath(self):
        """Test local media paths"""
        self.assertEqual(
            self.filepaths.local_media_filepath_rel("GerZNDnDZVjsOtardLuwfIBg"),
            "local_content/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )
        self.assertEqual(
            self.filepaths.local_media_filepath("GerZNDnDZVjsOtardLuwfIBg"),
            "/media_store/local_content/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )

    def test_local_media_thumbnail(self):
        """Test local media thumbnail paths"""
        self.assertEqual(
            self.filepaths.local_media_thumbnail_rel(
                "GerZNDnDZVjsOtardLuwfIBg", 800, 600, "image/jpeg", "scale"
            ),
            "local_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg-scale",
        )
        self.assertEqual(
            self.filepaths.local_media_thumbnail(
                "GerZNDnDZVjsOtardLuwfIBg", 800, 600, "image/jpeg", "scale"
            ),
            "/media_store/local_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg-scale",
        )

    def test_local_media_thumbnail_dir(self):
        """Test local media thumbnail directory paths"""
        self.assertEqual(
            self.filepaths.local_media_thumbnail_dir("GerZNDnDZVjsOtardLuwfIBg"),
            "/media_store/local_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )

    def test_remote_media_filepath(self):
        """Test remote media paths"""
        self.assertEqual(
            self.filepaths.remote_media_filepath_rel(
                "example.com", "GerZNDnDZVjsOtardLuwfIBg"
            ),
            "remote_content/example.com/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )
        self.assertEqual(
            self.filepaths.remote_media_filepath(
                "example.com", "GerZNDnDZVjsOtardLuwfIBg"
            ),
            "/media_store/remote_content/example.com/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )

    def test_remote_media_thumbnail(self):
        """Test remote media thumbnail paths"""
        self.assertEqual(
            self.filepaths.remote_media_thumbnail_rel(
                "example.com",
                "GerZNDnDZVjsOtardLuwfIBg",
                800,
                600,
                "image/jpeg",
                "scale",
            ),
            "remote_thumbnail/example.com/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg-scale",
        )
        self.assertEqual(
            self.filepaths.remote_media_thumbnail(
                "example.com",
                "GerZNDnDZVjsOtardLuwfIBg",
                800,
                600,
                "image/jpeg",
                "scale",
            ),
            "/media_store/remote_thumbnail/example.com/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg-scale",
        )

    def test_remote_media_thumbnail_legacy(self):
        """Test old-style remote media thumbnail paths"""
        self.assertEqual(
            self.filepaths.remote_media_thumbnail_rel_legacy(
                "example.com", "GerZNDnDZVjsOtardLuwfIBg", 800, 600, "image/jpeg"
            ),
            "remote_thumbnail/example.com/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg",
        )

    def test_remote_media_thumbnail_dir(self):
        """Test remote media thumbnail directory paths"""
        self.assertEqual(
            self.filepaths.remote_media_thumbnail_dir(
                "example.com", "GerZNDnDZVjsOtardLuwfIBg"
            ),
            "/media_store/remote_thumbnail/example.com/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )

    def test_url_cache_filepath(self):
        """Test URL cache paths"""
        self.assertEqual(
            self.filepaths.url_cache_filepath_rel("2020-01-02_GerZNDnDZVjsOtar"),
            "url_cache/2020-01-02/GerZNDnDZVjsOtar",
        )
        self.assertEqual(
            self.filepaths.url_cache_filepath("2020-01-02_GerZNDnDZVjsOtar"),
            "/media_store/url_cache/2020-01-02/GerZNDnDZVjsOtar",
        )

    def test_url_cache_filepath_legacy(self):
        """Test old-style URL cache paths"""
        self.assertEqual(
            self.filepaths.url_cache_filepath_rel("GerZNDnDZVjsOtardLuwfIBg"),
            "url_cache/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )
        self.assertEqual(
            self.filepaths.url_cache_filepath("GerZNDnDZVjsOtardLuwfIBg"),
            "/media_store/url_cache/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )

    def test_url_cache_filepath_dirs_to_delete(self):
        """Test URL cache cleanup paths"""
        self.assertEqual(
            self.filepaths.url_cache_filepath_dirs_to_delete(
                "2020-01-02_GerZNDnDZVjsOtar"
            ),
            ["/media_store/url_cache/2020-01-02"],
        )

    def test_url_cache_filepath_dirs_to_delete_legacy(self):
        """Test old-style URL cache cleanup paths"""
        self.assertEqual(
            self.filepaths.url_cache_filepath_dirs_to_delete(
                "GerZNDnDZVjsOtardLuwfIBg"
            ),
            [
                "/media_store/url_cache/Ge/rZ",
                "/media_store/url_cache/Ge",
            ],
        )

    def test_url_cache_thumbnail(self):
        """Test URL cache thumbnail paths"""
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_rel(
                "2020-01-02_GerZNDnDZVjsOtar", 800, 600, "image/jpeg", "scale"
            ),
            "url_cache_thumbnails/2020-01-02/GerZNDnDZVjsOtar/800-600-image-jpeg-scale",
        )
        self.assertEqual(
            self.filepaths.url_cache_thumbnail(
                "2020-01-02_GerZNDnDZVjsOtar", 800, 600, "image/jpeg", "scale"
            ),
            "/media_store/url_cache_thumbnails/2020-01-02/GerZNDnDZVjsOtar/800-600-image-jpeg-scale",
        )

    def test_url_cache_thumbnail_legacy(self):
        """Test old-style URL cache thumbnail paths"""
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_rel(
                "GerZNDnDZVjsOtardLuwfIBg", 800, 600, "image/jpeg", "scale"
            ),
            "url_cache_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg-scale",
        )
        self.assertEqual(
            self.filepaths.url_cache_thumbnail(
                "GerZNDnDZVjsOtardLuwfIBg", 800, 600, "image/jpeg", "scale"
            ),
            "/media_store/url_cache_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg/800-600-image-jpeg-scale",
        )

    def test_url_cache_thumbnail_directory(self):
        """Test URL cache thumbnail directory paths"""
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_directory_rel(
                "2020-01-02_GerZNDnDZVjsOtar"
            ),
            "url_cache_thumbnails/2020-01-02/GerZNDnDZVjsOtar",
        )
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_directory("2020-01-02_GerZNDnDZVjsOtar"),
            "/media_store/url_cache_thumbnails/2020-01-02/GerZNDnDZVjsOtar",
        )

    def test_url_cache_thumbnail_directory_legacy(self):
        """Test old-style URL cache thumbnail directory paths"""
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_directory_rel(
                "GerZNDnDZVjsOtardLuwfIBg"
            ),
            "url_cache_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_directory("GerZNDnDZVjsOtardLuwfIBg"),
            "/media_store/url_cache_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg",
        )

    def test_url_cache_thumbnail_dirs_to_delete(self):
        """Test URL cache thumbnail cleanup paths"""
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_dirs_to_delete(
                "2020-01-02_GerZNDnDZVjsOtar"
            ),
            [
                "/media_store/url_cache_thumbnails/2020-01-02/GerZNDnDZVjsOtar",
                "/media_store/url_cache_thumbnails/2020-01-02",
            ],
        )

    def test_url_cache_thumbnail_dirs_to_delete_legacy(self):
        """Test old-style URL cache thumbnail cleanup paths"""
        self.assertEqual(
            self.filepaths.url_cache_thumbnail_dirs_to_delete(
                "GerZNDnDZVjsOtardLuwfIBg"
            ),
            [
                "/media_store/url_cache_thumbnails/Ge/rZ/NDnDZVjsOtardLuwfIBg",
                "/media_store/url_cache_thumbnails/Ge/rZ",
                "/media_store/url_cache_thumbnails/Ge",
            ],
        )

    def test_server_name_validation(self):
        """Test validation of server names"""
        self._test_path_validation(
            [
                "remote_media_filepath_rel",
                "remote_media_filepath",
                "remote_media_thumbnail_rel",
                "remote_media_thumbnail",
                "remote_media_thumbnail_rel_legacy",
                "remote_media_thumbnail_dir",
            ],
            parameter="server_name",
            valid_values=[
                "matrix.org",
                "matrix.org:8448",
                "matrix-federation.matrix.org",
                "matrix-federation.matrix.org:8448",
                "10.1.12.123",
                "10.1.12.123:8448",
                "[fd00:abcd::ffff]",
                "[fd00:abcd::ffff]:8448",
            ],
            invalid_values=[
                "/matrix.org",
                "matrix.org/..",
                "matrix.org\x00",
                "",
                ".",
                "..",
                "/",
            ],
        )

    def test_file_id_validation(self):
        """Test validation of local, remote and legacy URL cache file / media IDs"""
        # File / media IDs get split into three parts to form paths, consisting of the
        # first two characters, next two characters and rest of the ID.
        valid_file_ids = [
            "GerZNDnDZVjsOtardLuwfIBg",
            # Unexpected, but produces an acceptable path:
            "GerZN",  # "N" becomes the last directory
        ]
        invalid_file_ids = [
            "/erZNDnDZVjsOtardLuwfIBg",
            "Ge/ZNDnDZVjsOtardLuwfIBg",
            "GerZ/DnDZVjsOtardLuwfIBg",
            "GerZ/..",
            "G\x00rZNDnDZVjsOtardLuwfIBg",
            "Ger\x00NDnDZVjsOtardLuwfIBg",
            "GerZNDnDZVjsOtardLuwfIBg\x00",
            "",
            "Ge",
            "GerZ",
            "GerZ.",
            "..rZNDnDZVjsOtardLuwfIBg",
            "Ge..NDnDZVjsOtardLuwfIBg",
            "GerZ..",
            "GerZ/",
        ]

        self._test_path_validation(
            [
                "local_media_filepath_rel",
                "local_media_filepath",
                "local_media_thumbnail_rel",
                "local_media_thumbnail",
                "local_media_thumbnail_dir",
                # Legacy URL cache media IDs
                "url_cache_filepath_rel",
                "url_cache_filepath",
                # `url_cache_filepath_dirs_to_delete` is tested below.
                "url_cache_thumbnail_rel",
                "url_cache_thumbnail",
                "url_cache_thumbnail_directory_rel",
                "url_cache_thumbnail_directory",
                "url_cache_thumbnail_dirs_to_delete",
            ],
            parameter="media_id",
            valid_values=valid_file_ids,
            invalid_values=invalid_file_ids,
        )

        # `url_cache_filepath_dirs_to_delete` ignores what would be the last path
        # component, so only the first 4 characters matter.
        self._test_path_validation(
            [
                "url_cache_filepath_dirs_to_delete",
            ],
            parameter="media_id",
            valid_values=valid_file_ids,
            invalid_values=[
                "/erZNDnDZVjsOtardLuwfIBg",
                "Ge/ZNDnDZVjsOtardLuwfIBg",
                "G\x00rZNDnDZVjsOtardLuwfIBg",
                "Ger\x00NDnDZVjsOtardLuwfIBg",
                "",
                "Ge",
                "..rZNDnDZVjsOtardLuwfIBg",
                "Ge..NDnDZVjsOtardLuwfIBg",
            ],
        )

        self._test_path_validation(
            [
                "remote_media_filepath_rel",
                "remote_media_filepath",
                "remote_media_thumbnail_rel",
                "remote_media_thumbnail",
                "remote_media_thumbnail_rel_legacy",
                "remote_media_thumbnail_dir",
            ],
            parameter="file_id",
            valid_values=valid_file_ids,
            invalid_values=invalid_file_ids,
        )

    def test_url_cache_media_id_validation(self):
        """Test validation of URL cache media IDs"""
        self._test_path_validation(
            [
                "url_cache_filepath_rel",
                "url_cache_filepath",
                # `url_cache_filepath_dirs_to_delete` only cares about the date prefix
                "url_cache_thumbnail_rel",
                "url_cache_thumbnail",
                "url_cache_thumbnail_directory_rel",
                "url_cache_thumbnail_directory",
                "url_cache_thumbnail_dirs_to_delete",
            ],
            parameter="media_id",
            valid_values=[
                "2020-01-02_GerZNDnDZVjsOtar",
                "2020-01-02_G",  # Unexpected, but produces an acceptable path
            ],
            invalid_values=[
                "2020-01-02",
                "2020-01-02-",
                "2020-01-02-.",
                "2020-01-02-..",
                "2020-01-02-/",
                "2020-01-02-/GerZNDnDZVjsOtar",
                "2020-01-02-GerZNDnDZVjsOtar/..",
                "2020-01-02-GerZNDnDZVjsOtar\x00",
            ],
        )

    def test_content_type_validation(self):
        """Test validation of thumbnail content types"""
        self._test_path_validation(
            [
                "local_media_thumbnail_rel",
                "local_media_thumbnail",
                "remote_media_thumbnail_rel",
                "remote_media_thumbnail",
                "remote_media_thumbnail_rel_legacy",
                "url_cache_thumbnail_rel",
                "url_cache_thumbnail",
            ],
            parameter="content_type",
            valid_values=[
                "image/jpeg",
            ],
            invalid_values=[
                "",  # ValueError: not enough values to unpack
                "image/jpeg/abc",  # ValueError: too many values to unpack
                "image/jpeg\x00",
            ],
        )

    def test_thumbnail_method_validation(self):
        """Test validation of thumbnail methods"""
        self._test_path_validation(
            [
                "local_media_thumbnail_rel",
                "local_media_thumbnail",
                "remote_media_thumbnail_rel",
                "remote_media_thumbnail",
                "url_cache_thumbnail_rel",
                "url_cache_thumbnail",
            ],
            parameter="method",
            valid_values=[
                "crop",
                "scale",
            ],
            invalid_values=[
                "/scale",
                "scale/..",
                "scale\x00",
                "/",
            ],
        )

    def _test_path_validation(
        self,
        methods: Iterable[str],
        parameter: str,
        valid_values: Iterable[str],
        invalid_values: Iterable[str],
    ):
        """Test that the specified methods validate the named parameter as expected

        Args:
            methods: The names of `MediaFilePaths` methods to test
            parameter: The name of the parameter to test
            valid_values: A list of parameter values that are expected to be accepted
            invalid_values: A list of parameter values that are expected to be rejected

        Raises:
            AssertionError: If a value was accepted when it should have failed
                validation.
            ValueError: If a value failed validation when it should have been accepted.
        """
        for method in methods:
            get_path = getattr(self.filepaths, method)

            parameters = inspect.signature(get_path).parameters
            kwargs = {
                "server_name": "matrix.org",
                "media_id": "GerZNDnDZVjsOtardLuwfIBg",
                "file_id": "GerZNDnDZVjsOtardLuwfIBg",
                "width": 800,
                "height": 600,
                "content_type": "image/jpeg",
                "method": "scale",
            }

            if get_path.__name__.startswith("url_"):
                kwargs["media_id"] = "2020-01-02_GerZNDnDZVjsOtar"

            kwargs = {k: v for k, v in kwargs.items() if k in parameters}
            kwargs.pop(parameter)

            for value in valid_values:
                kwargs[parameter] = value
                get_path(**kwargs)
                # No exception should be raised

            for value in invalid_values:
                with self.assertRaises(ValueError):
                    kwargs[parameter] = value
                    path_or_list = get_path(**kwargs)
                    self.fail(
                        f"{value!r} unexpectedly passed validation: "
                        f"{method} returned {path_or_list!r}"
                    )
