# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from synapse.rest.media.v1._base import get_filename_from_headers

from tests import unittest


class GetFileNameFromHeadersTests(unittest.TestCase):
    # input -> expected result
    TEST_CASES = {
        b"inline; filename=abc.txt": u"abc.txt",
        b'inline; filename="azerty"': u"azerty",
        b'inline; filename="aze%20rty"': u"aze%20rty",
        b'inline; filename="aze\"rty"': u'aze"rty',
        b'inline; filename="azer;ty"': u"azer;ty",
        b"inline; filename*=utf-8''foo%C2%A3bar": u"foo£bar",
    }

    def tests(self):
        for hdr, expected in self.TEST_CASES.items():
            res = get_filename_from_headers({b'Content-Disposition': [hdr]})
            self.assertEqual(
                res,
                expected,
                "expected output for %s to be %s but was %s" % (hdr, expected, res),
            )
