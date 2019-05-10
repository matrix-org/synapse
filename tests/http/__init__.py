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
import os.path

from OpenSSL import SSL


def get_test_cert_file():
    """get the path to the test cert"""

    # the cert file itself is made with:
    #
    # openssl req -x509 -newkey rsa:4096 -keyout server.pem  -out server.pem -days 36500 \
    #     -nodes -subj '/CN=testserv'
    return os.path.join(os.path.dirname(__file__), 'server.pem')


class ServerTLSContext(object):
    """A TLS Context which presents our test cert."""

    def __init__(self):
        self.filename = get_test_cert_file()

    def getContext(self):
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.use_certificate_file(self.filename)
        ctx.use_privatekey_file(self.filename)
        return ctx
