# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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


from tests import unittest

from synapse.federation.transport.client import _create_path


class PathEncodeTestCase(unittest.TestCase):
    def test_path_encoding(self):
        P = "/foo"

        self.assertEqual("/foo/bar", _create_path(P, "/bar"))
        self.assertEqual("/foo/bar/e", _create_path(P, "/bar/%s", "e"))
        self.assertEqual("/foo/bar/%24e", _create_path(P, "/bar/%s", "$e"))
        self.assertEqual("/foo/bar/%2Fe%2F", _create_path(P, "/bar/%s", "/e/"))
        self.assertEqual("/foo/bar/x/y", _create_path(P, "/bar/%s/%s", "x", "y"))
