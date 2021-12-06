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
