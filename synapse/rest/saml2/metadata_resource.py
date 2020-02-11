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


import saml2.metadata

from twisted.web.resource import Resource


class SAML2MetadataResource(Resource):
    """A Twisted web resource which renders the SAML metadata"""

    isLeaf = 1

    def __init__(self, hs):
        Resource.__init__(self)
        self.sp_config = hs.config.saml2_sp_config

    def render_GET(self, request):
        metadata_xml = saml2.metadata.create_metadata_string(
            configfile=None, config=self.sp_config
        )
        request.setHeader(b"Content-Type", b"text/xml; charset=utf-8")
        return metadata_xml
