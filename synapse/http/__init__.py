# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
import re

from twisted.internet import task
from twisted.web.client import FileBodyProducer

from synapse.api.errors import SynapseError


class RequestTimedOutError(SynapseError):
    """Exception representing timeout of an outbound request"""

    def __init__(self, msg):
        super().__init__(504, msg)


ACCESS_TOKEN_RE = re.compile(r"(\?.*access(_|%5[Ff])token=)[^&]*(.*)$")
CLIENT_SECRET_RE = re.compile(r"(\?.*client(_|%5[Ff])secret=)[^&]*(.*)$")


def redact_uri(uri):
    """Strips sensitive information from the uri replaces with <redacted>"""
    uri = ACCESS_TOKEN_RE.sub(r"\1<redacted>\3", uri)
    return CLIENT_SECRET_RE.sub(r"\1<redacted>\3", uri)


class QuieterFileBodyProducer(FileBodyProducer):
    """Wrapper for FileBodyProducer that avoids CRITICAL errors when the connection drops.

    Workaround for https://github.com/matrix-org/synapse/issues/4003 /
    https://twistedmatrix.com/trac/ticket/6528
    """

    def stopProducing(self):
        try:
            FileBodyProducer.stopProducing(self)
        except task.TaskStopped:
            pass
