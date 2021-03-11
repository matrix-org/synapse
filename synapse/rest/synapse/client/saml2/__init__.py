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

import logging

from twisted.web.resource import Resource

from synapse.rest.synapse.client.saml2.metadata_resource import SAML2MetadataResource
from synapse.rest.synapse.client.saml2.response_resource import SAML2ResponseResource

logger = logging.getLogger(__name__)


class SAML2Resource(Resource):
    def __init__(self, hs):
        Resource.__init__(self)
        self.putChild(b"metadata.xml", SAML2MetadataResource(hs))
        self.putChild(b"authn_response", SAML2ResponseResource(hs))


__all__ = ["SAML2Resource"]
