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

"""
Injectable secrets module for Synapse.

See https://docs.python.org/3/library/secrets.html#module-secrets for the API
used in Python 3.6, and the API emulated in Python 2.7.
"""
import sys

# secrets is available since python 3.6
if sys.version_info[0:2] >= (3, 6):
    import secrets

    class Secrets:
        def token_bytes(self, nbytes=32):
            return secrets.token_bytes(nbytes)

        def token_hex(self, nbytes=32):
            return secrets.token_hex(nbytes)


else:
    import binascii
    import os

    class Secrets:
        def token_bytes(self, nbytes=32):
            return os.urandom(nbytes)

        def token_hex(self, nbytes=32):
            return binascii.hexlify(self.token_bytes(nbytes)).decode("ascii")
