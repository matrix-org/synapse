# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import defer, threads
import twisted.internet.error
import twisted.web.http
from twisted.web.resource import Resource

from .upload_resource import UploadResource
from .download_resource import DownloadResource
from .thumbnail_resource import ThumbnailResource
from .identicon_resource import IdenticonResource
from .preview_url_resource import PreviewUrlResource
from .filepath import MediaFilePaths
from .thumbnailer import Thumbnailer

from synapse.http.matrixfederationclient import MatrixFederationHttpClient
from synapse.util.stringutils import random_string
from synapse.api.errors import SynapseError, HttpResponseException, \
    NotFoundError

from synapse.util.async import Linearizer
from synapse.util.stringutils import is_ascii
from synapse.util.logcontext import make_deferred_yieldable, preserve_fn
from synapse.util.retryutils import NotRetryingDestination

import os
import errno
import shutil

import cgi
import logging
import urlparse

logger = logging.getLogger(__name__)


UPDATE_RECENTLY_ACCESSED_REMOTES_TS = 60 * 1000


class MediaRepository(object):
    def __init__(self, hs):
        self.auth = hs.get_auth()
        self.client = MatrixFederationHttpClient(hs)
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.max_upload_size = hs.config.max_upload_size
        self.max_image_pixels = hs.config.max_image_pixels

        self.primary_base_path = hs.config.media_store_path
        self.filepaths = MediaFilePaths(self.primary_base_path)

        self.backup_base_path = hs.config.backup_media_store_path

        self.synchronous_backup_media_store = hs.config.synchronous_backup_media_store

        self.dynamic_thumbnails = hs.config.dynamic_thumbnails
        self.thumbnail_requirements = hs.config.thumbnail_requirements

        self.remote_media_linearizer = Linearizer(name="media_remote")

        self.recently_accessed_remotes = set()

        self.clock.looping_call(
            self._update_recently_accessed_remotes,
            UPDATE_RECENTLY_ACCESSED_REMOTES_TS
        )

    @defer.inlineCallbacks
    def _update_recently_accessed_remotes(self):
        media = self.recently_accessed_remotes
        self.recently_accessed_remotes = set()

        yield self.store.update_cached_last_access_time(
            media, self.clock.time_msec()
        )

    @staticmethod
    def _makedirs(filepath):
        dirname = os.path.dirname(filepath)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

    @staticmethod
    def _write_file_synchronously(source, fname):
        """Write `source` to the path `fname` synchronously. Should be called
        from a thread.

        Args:
            source: A file like object to be written
            fname (str): Path to write to
        """
        MediaRepository._makedirs(fname)
        source.seek(0)  # Ensure we read from the start of the file
        with open(fname, "wb") as f:
            shutil.copyfileobj(source, f)

    @defer.inlineCallbacks
    def write_to_file_and_backup(self, source, path):
        """Write `source` to the on disk media store, and also the backup store
        if configured.

        Args:
            source: A file like object that should be written
            path (str): Relative path to write file to

        Returns:
            Deferred[str]: the file path written to in the primary media store
        """
        fname = os.path.join(self.primary_base_path, path)

        # Write to the main repository
        yield make_deferred_yieldable(threads.deferToThread(
            self._write_file_synchronously, source, fname,
        ))

        # Write to backup repository
        yield self.copy_to_backup(path)

        defer.returnValue(fname)

    @defer.inlineCallbacks
    def copy_to_backup(self, path):
        """Copy a file from the primary to backup media store, if configured.

        Args:
            path(str): Relative path to write file to
        """
        if self.backup_base_path:
            primary_fname = os.path.join(self.primary_base_path, path)
            backup_fname = os.path.join(self.backup_base_path, path)

            # We can either wait for successful writing to the backup repository
            # or write in the background and immediately return
            if self.synchronous_backup_media_store:
                yield make_deferred_yieldable(threads.deferToThread(
                    shutil.copyfile, primary_fname, backup_fname,
                ))
            else:
                preserve_fn(threads.deferToThread)(
                    shutil.copyfile, primary_fname, backup_fname,
                )

    @defer.inlineCallbacks
    def create_content(self, media_type, upload_name, content, content_length,
                       auth_user):
        """Store uploaded content for a local user and return the mxc URL

        Args:
            media_type(str): The content type of the file
            upload_name(str): The name of the file
            content: A file like object that is the content to store
            content_length(int): The length of the content
            auth_user(str): The user_id of the uploader

        Returns:
            Deferred[str]: The mxc url of the stored content
        """
        media_id = random_string(24)

        fname = yield self.write_to_file_and_backup(
            content, self.filepaths.local_media_filepath_rel(media_id)
        )

        logger.info("Stored local media in file %r", fname)

        yield self.store.store_local_media(
            media_id=media_id,
            media_type=media_type,
            time_now_ms=self.clock.time_msec(),
            upload_name=upload_name,
            media_length=content_length,
            user_id=auth_user,
        )
        media_info = {
            "media_type": media_type,
            "media_length": content_length,
        }

        yield self._generate_thumbnails(None, media_id, media_info)

        defer.returnValue("mxc://%s/%s" % (self.server_name, media_id))

    @defer.inlineCallbacks
    def get_remote_media(self, server_name, media_id):
        key = (server_name, media_id)
        with (yield self.remote_media_linearizer.queue(key)):
            media_info = yield self._get_remote_media_impl(server_name, media_id)
        defer.returnValue(media_info)

    @defer.inlineCallbacks
    def _get_remote_media_impl(self, server_name, media_id):
        media_info = yield self.store.get_cached_remote_media(
            server_name, media_id
        )
        if not media_info:
            media_info = yield self._download_remote_file(
                server_name, media_id
            )
        elif media_info["quarantined_by"]:
            raise NotFoundError()
        else:
            self.recently_accessed_remotes.add((server_name, media_id))
            yield self.store.update_cached_last_access_time(
                [(server_name, media_id)], self.clock.time_msec()
            )
        defer.returnValue(media_info)

    @defer.inlineCallbacks
    def _download_remote_file(self, server_name, media_id):
        file_id = random_string(24)

        fpath = self.filepaths.remote_media_filepath_rel(
            server_name, file_id
        )
        fname = os.path.join(self.primary_base_path, fpath)
        self._makedirs(fname)

        try:
            with open(fname, "wb") as f:
                request_path = "/".join((
                    "/_matrix/media/v1/download", server_name, media_id,
                ))
                try:
                    length, headers = yield self.client.get_file(
                        server_name, request_path, output_stream=f,
                        max_size=self.max_upload_size, args={
                            # tell the remote server to 404 if it doesn't
                            # recognise the server_name, to make sure we don't
                            # end up with a routing loop.
                            "allow_remote": "false",
                        }
                    )
                except twisted.internet.error.DNSLookupError as e:
                    logger.warn("HTTP error fetching remote media %s/%s: %r",
                                server_name, media_id, e)
                    raise NotFoundError()

                except HttpResponseException as e:
                    logger.warn("HTTP error fetching remote media %s/%s: %s",
                                server_name, media_id, e.response)
                    if e.code == twisted.web.http.NOT_FOUND:
                        raise SynapseError.from_http_response_exception(e)
                    raise SynapseError(502, "Failed to fetch remote media")

                except SynapseError:
                    logger.exception("Failed to fetch remote media %s/%s",
                                     server_name, media_id)
                    raise
                except NotRetryingDestination:
                    logger.warn("Not retrying destination %r", server_name)
                    raise SynapseError(502, "Failed to fetch remote media")
                except Exception:
                    logger.exception("Failed to fetch remote media %s/%s",
                                     server_name, media_id)
                    raise SynapseError(502, "Failed to fetch remote media")

            yield self.copy_to_backup(fpath)

            media_type = headers["Content-Type"][0]
            time_now_ms = self.clock.time_msec()

            content_disposition = headers.get("Content-Disposition", None)
            if content_disposition:
                _, params = cgi.parse_header(content_disposition[0],)
                upload_name = None

                # First check if there is a valid UTF-8 filename
                upload_name_utf8 = params.get("filename*", None)
                if upload_name_utf8:
                    if upload_name_utf8.lower().startswith("utf-8''"):
                        upload_name = upload_name_utf8[7:]

                # If there isn't check for an ascii name.
                if not upload_name:
                    upload_name_ascii = params.get("filename", None)
                    if upload_name_ascii and is_ascii(upload_name_ascii):
                        upload_name = upload_name_ascii

                if upload_name:
                    upload_name = urlparse.unquote(upload_name)
                    try:
                        upload_name = upload_name.decode("utf-8")
                    except UnicodeDecodeError:
                        upload_name = None
            else:
                upload_name = None

            logger.info("Stored remote media in file %r", fname)

            yield self.store.store_cached_remote_media(
                origin=server_name,
                media_id=media_id,
                media_type=media_type,
                time_now_ms=self.clock.time_msec(),
                upload_name=upload_name,
                media_length=length,
                filesystem_id=file_id,
            )
        except Exception:
            os.remove(fname)
            raise

        media_info = {
            "media_type": media_type,
            "media_length": length,
            "upload_name": upload_name,
            "created_ts": time_now_ms,
            "filesystem_id": file_id,
        }

        yield self._generate_thumbnails(
            server_name, media_id, media_info
        )

        defer.returnValue(media_info)

    def _get_thumbnail_requirements(self, media_type):
        return self.thumbnail_requirements.get(media_type, ())

    def _generate_thumbnail(self, thumbnailer, t_width, t_height,
                            t_method, t_type):
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width, m_height, self.max_image_pixels
            )
            return

        if t_method == "crop":
            t_byte_source = thumbnailer.crop(t_width, t_height, t_type)
        elif t_method == "scale":
            t_width, t_height = thumbnailer.aspect(t_width, t_height)
            t_width = min(m_width, t_width)
            t_height = min(m_height, t_height)
            t_byte_source = thumbnailer.scale(t_width, t_height, t_type)
        else:
            t_byte_source = None

        return t_byte_source

    @defer.inlineCallbacks
    def generate_local_exact_thumbnail(self, media_id, t_width, t_height,
                                       t_method, t_type):
        input_path = self.filepaths.local_media_filepath(media_id)

        thumbnailer = Thumbnailer(input_path)
        t_byte_source = yield make_deferred_yieldable(threads.deferToThread(
            self._generate_thumbnail,
            thumbnailer, t_width, t_height, t_method, t_type
        ))

        if t_byte_source:
            try:
                output_path = yield self.write_to_file_and_backup(
                    t_byte_source,
                    self.filepaths.local_media_thumbnail_rel(
                        media_id, t_width, t_height, t_type, t_method
                    )
                )
            finally:
                t_byte_source.close()

            logger.info("Stored thumbnail in file %r", output_path)

            t_len = os.path.getsize(output_path)

            yield self.store.store_local_thumbnail(
                media_id, t_width, t_height, t_type, t_method, t_len
            )

            defer.returnValue(output_path)

    @defer.inlineCallbacks
    def generate_remote_exact_thumbnail(self, server_name, file_id, media_id,
                                        t_width, t_height, t_method, t_type):
        input_path = self.filepaths.remote_media_filepath(server_name, file_id)

        thumbnailer = Thumbnailer(input_path)
        t_byte_source = yield make_deferred_yieldable(threads.deferToThread(
            self._generate_thumbnail,
            thumbnailer, t_width, t_height, t_method, t_type
        ))

        if t_byte_source:
            try:
                output_path = yield self.write_to_file_and_backup(
                    t_byte_source,
                    self.filepaths.remote_media_thumbnail_rel(
                        server_name, file_id, t_width, t_height, t_type, t_method
                    )
                )
            finally:
                t_byte_source.close()

            logger.info("Stored thumbnail in file %r", output_path)

            t_len = os.path.getsize(output_path)

            yield self.store.store_remote_media_thumbnail(
                server_name, media_id, file_id,
                t_width, t_height, t_type, t_method, t_len
            )

            defer.returnValue(output_path)

    @defer.inlineCallbacks
    def _generate_thumbnails(self, server_name, media_id, media_info, url_cache=False):
        """Generate and store thumbnails for an image.

        Args:
            server_name(str|None): The server name if remote media, else None if local
            media_id(str)
            media_info(dict)
            url_cache(bool): If we are thumbnailing images downloaded for the URL cache,
                used exclusively by the url previewer

        Returns:
            Deferred[dict]: Dict with "width" and "height" keys of original image
        """
        media_type = media_info["media_type"]
        file_id = media_info.get("filesystem_id")
        requirements = self._get_thumbnail_requirements(media_type)
        if not requirements:
            return

        if server_name:
            input_path = self.filepaths.remote_media_filepath(server_name, file_id)
        elif url_cache:
            input_path = self.filepaths.url_cache_filepath(media_id)
        else:
            input_path = self.filepaths.local_media_filepath(media_id)

        thumbnailer = Thumbnailer(input_path)
        m_width = thumbnailer.width
        m_height = thumbnailer.height

        if m_width * m_height >= self.max_image_pixels:
            logger.info(
                "Image too large to thumbnail %r x %r > %r",
                m_width, m_height, self.max_image_pixels
            )
            return

        # We deduplicate the thumbnail sizes by ignoring the cropped versions if
        # they have the same dimensions of a scaled one.
        thumbnails = {}
        for r_width, r_height, r_method, r_type in requirements:
            if r_method == "crop":
                thumbnails.setdefault((r_width, r_height, r_type), r_method)
            elif r_method == "scale":
                t_width, t_height = thumbnailer.aspect(r_width, r_height)
                t_width = min(m_width, t_width)
                t_height = min(m_height, t_height)
                thumbnails[(t_width, t_height, r_type)] = r_method

        # Now we generate the thumbnails for each dimension, store it
        for (t_width, t_height, t_type), t_method in thumbnails.iteritems():
            # Work out the correct file name for thumbnail
            if server_name:
                file_path = self.filepaths.remote_media_thumbnail_rel(
                    server_name, file_id, t_width, t_height, t_type, t_method
                )
            elif url_cache:
                file_path = self.filepaths.url_cache_thumbnail_rel(
                    media_id, t_width, t_height, t_type, t_method
                )
            else:
                file_path = self.filepaths.local_media_thumbnail_rel(
                    media_id, t_width, t_height, t_type, t_method
                )

            # Generate the thumbnail
            if t_method == "crop":
                t_byte_source = yield make_deferred_yieldable(threads.deferToThread(
                    thumbnailer.crop,
                    t_width, t_height, t_type,
                ))
            elif t_method == "scale":
                t_byte_source = yield make_deferred_yieldable(threads.deferToThread(
                    thumbnailer.scale,
                    t_width, t_height, t_type,
                ))
            else:
                logger.error("Unrecognized method: %r", t_method)
                continue

            if not t_byte_source:
                continue

            try:
                # Write to disk
                output_path = yield self.write_to_file_and_backup(
                    t_byte_source, file_path,
                )
            finally:
                t_byte_source.close()

            t_len = os.path.getsize(output_path)

            # Write to database
            if server_name:
                yield self.store.store_remote_media_thumbnail(
                    server_name, media_id, file_id,
                    t_width, t_height, t_type, t_method, t_len
                )
            else:
                yield self.store.store_local_thumbnail(
                    media_id, t_width, t_height, t_type, t_method, t_len
                )

        defer.returnValue({
            "width": m_width,
            "height": m_height,
        })

    @defer.inlineCallbacks
    def delete_old_remote_media(self, before_ts):
        old_media = yield self.store.get_remote_media_before(before_ts)

        deleted = 0

        for media in old_media:
            origin = media["media_origin"]
            media_id = media["media_id"]
            file_id = media["filesystem_id"]
            key = (origin, media_id)

            logger.info("Deleting: %r", key)

            # TODO: Should we delete from the backup store

            with (yield self.remote_media_linearizer.queue(key)):
                full_path = self.filepaths.remote_media_filepath(origin, file_id)
                try:
                    os.remove(full_path)
                except OSError as e:
                    logger.warn("Failed to remove file: %r", full_path)
                    if e.errno == errno.ENOENT:
                        pass
                    else:
                        continue

                thumbnail_dir = self.filepaths.remote_media_thumbnail_dir(
                    origin, file_id
                )
                shutil.rmtree(thumbnail_dir, ignore_errors=True)

                yield self.store.delete_remote_media(origin, media_id)
                deleted += 1

        defer.returnValue({"deleted": deleted})


class MediaRepositoryResource(Resource):
    """File uploading and downloading.

    Uploads are POSTed to a resource which returns a token which is used to GET
    the download::

        => POST /_matrix/media/v1/upload HTTP/1.1
           Content-Type: <media-type>
           Content-Length: <content-length>

           <media>

        <= HTTP/1.1 200 OK
           Content-Type: application/json

           { "content_uri": "mxc://<server-name>/<media-id>" }

        => GET /_matrix/media/v1/download/<server-name>/<media-id> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: <media-type>
           Content-Disposition: attachment;filename=<upload-filename>

           <media>

    Clients can get thumbnails by supplying a desired width and height and
    thumbnailing method::

        => GET /_matrix/media/v1/thumbnail/<server_name>
                /<media-id>?width=<w>&height=<h>&method=<m> HTTP/1.1

        <= HTTP/1.1 200 OK
           Content-Type: image/jpeg or image/png

           <thumbnail>

    The thumbnail methods are "crop" and "scale". "scale" trys to return an
    image where either the width or the height is smaller than the requested
    size. The client should then scale and letterbox the image if it needs to
    fit within a given rectangle. "crop" trys to return an image where the
    width and height are close to the requested size and the aspect matches
    the requested size. The client should scale the image if it needs to fit
    within a given rectangle.
    """

    def __init__(self, hs):
        Resource.__init__(self)

        media_repo = hs.get_media_repository()

        self.putChild("upload", UploadResource(hs, media_repo))
        self.putChild("download", DownloadResource(hs, media_repo))
        self.putChild("thumbnail", ThumbnailResource(hs, media_repo))
        self.putChild("identicon", IdenticonResource())
        if hs.config.url_preview_enabled:
            self.putChild("preview_url", PreviewUrlResource(hs, media_repo))
