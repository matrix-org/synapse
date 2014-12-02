# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from .upload_resource import UploadResource
from .filepath import MediaFilePaths

from twisted.web.resource import Resource

import logging

logger = logging.getLogger(__name__)


class MediaRepositoryResource(Resource):
    """Profiles file uploading and downloading.

    Uploads are POSTed to a resource which returns a token which is used to GET
    the download::

        => POST /_matrix/media/v1/upload HTTP/1.1
           Content-Type: <media-type>

           <media>

        <= HTTP/1.1 200 OK
           Content-Type: application/json

           { "token": <media-id> }

        => GET /_matrix/media/v1/download/<media-id> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: <media-type>
           Content-Disposition: attachment;filename=<upload-filename>

           <media>

    Clients can get thumbnails by supplying a desired width and height::

        => GET /_matrix/media/v1/thumbnail/<media-id>?width=<w>&height=<h> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: image/jpeg or image/png

           <thumbnail>
    """

    def __init__(self, hs):
        Resource.__init__(self)
        filepaths = MediaFilePaths(hs.config.media_store_path)
        self.putChild("upload", UploadResource(hs, filepaths))
