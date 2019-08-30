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

import attr
from constantly import NamedConstant, Names
from zope.interface import implementer

from .interfaces import IRemoteAddress


class Protocols(Names):
    HTTP = NamedConstant()
    HTTPS = NamedConstant()

    @staticmethod
    def from_scheme(scheme: str):
        if scheme == "http":
            return Protocols.HTTP
        elif scheme == "https":
            return Protocols.HTTPS

        raise ValueError("Don't know about %s" % (scheme,))


@attr.s(frozen=True)
@implementer(IRemoteAddress)
class RemoteAddress:
    name = attr.ib(cmp=True, repr=False)
    addresses = attr.ib(cmp=False, repr=False)
    port = attr.ib(cmp=True)
    protocol = attr.ib(cmp=True)


@attr.s(frozen=True)
class ResolvedFederationAddress(RemoteAddress):
    matrix_server_name = attr.ib(cmp=True)
