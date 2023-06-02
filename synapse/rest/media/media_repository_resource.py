# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING

from synapse.config._base import ConfigError
from synapse.http.server import UnrecognizedRequestResource

from .config_resource import MediaConfigResource
from .download_resource import DownloadResource
from .preview_url_resource import PreviewUrlResource
from .thumbnail_resource import ThumbnailResource
from .upload_resource import UploadResource

if TYPE_CHECKING:
    from synapse.server import HomeServer


class MediaRepositoryResource(UnrecognizedRequestResource):
    """File uploading and downloading.

    Uploads are POSTed to a resource which returns a token which is used to GET
    the download::

        => POST /_matrix/media/r0/upload HTTP/1.1
           Content-Type: <media-type>
           Content-Length: <content-length>

           <media>

        <= HTTP/1.1 200 OK
           Content-Type: application/json

           { "content_uri": "mxc://<server-name>/<media-id>" }

        => GET /_matrix/media/r0/download/<server-name>/<media-id> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: <media-type>
           Content-Disposition: attachment;filename=<upload-filename>

           <media>

    Clients can get thumbnails by supplying a desired width and height and
    thumbnailing method::

        => GET /_matrix/media/r0/thumbnail/<server_name>
                /<media-id>?width=<w>&height=<h>&method=<m> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: image/jpeg or image/png

           <thumbnail>

    The thumbnail methods are "crop" and "scale". "scale" tries to return an
    image where either the width or the height is smaller than the requested
    size. The client should then scale and letterbox the image if it needs to
    fit within a given rectangle. "crop" tries to return an image where the
    width and height are close to the requested size and the aspect matches
    the requested size. The client should scale the image if it needs to fit
    within a given rectangle.
    """

    def __init__(self, hs: "HomeServer"):
        # If we're not configured to use it, raise if we somehow got here.
        if not hs.config.media.can_load_media_repo:
            raise ConfigError("Synapse is not configured to use a media repo.")

        super().__init__()
        media_repo = hs.get_media_repository()

        self.putChild(b"upload", UploadResource(hs, media_repo))
        self.putChild(b"download", DownloadResource(hs, media_repo))
        self.putChild(
            b"thumbnail", ThumbnailResource(hs, media_repo, media_repo.media_storage)
        )
        if hs.config.media.url_preview_enabled:
            self.putChild(
                b"preview_url",
                PreviewUrlResource(hs, media_repo, media_repo.media_storage),
            )
        self.putChild(b"config", MediaConfigResource(hs))
