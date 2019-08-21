# -*- coding: utf-8 -*-

# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import hashlib

import unpaddedbase64


def sha256_and_url_safe_base64(input_text):
    """SHA256 hash an input string, encode the digest as url-safe base64, and
    return

    :param input_text: string to hash
    :type input_text: str

    :returns a sha256 hashed and url-safe base64 encoded digest
    :rtype: str
    """
    digest = hashlib.sha256(input_text.encode()).digest()
    return unpaddedbase64.encode_base64(digest, urlsafe=True)
