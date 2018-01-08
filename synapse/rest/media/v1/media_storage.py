# -*- coding: utf-8 -*-
# Copyright 2018 New Vecotr Ltd
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
from twisted.protocols.basic import FileSender

from ._base import Responder

from synapse.util.logcontext import make_deferred_yieldable

import contextlib
import os
import logging
import shutil

logger = logging.getLogger(__name__)


class MediaStorage(object):
    """Responsible for storing/fetching files from local sources.
    """

    def __init__(self, local_media_directory, filepaths):
        self.local_media_directory = local_media_directory
        self.filepaths = filepaths

    @defer.inlineCallbacks
    def store_file(self, source, file_info):
        """Write `source` to the on disk media store, and also any other
        configured storage providers

        Args:
            source: A file like object that should be written
            file_info (FileInfo): Info about the file to store

        Returns:
            Deferred[str]: the file path written to in the primary media store
        """
        path = self._file_info_to_path(file_info)
        fname = os.path.join(self.local_media_directory, path)

        dirname = os.path.dirname(fname)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        # Write to the main repository
        yield make_deferred_yieldable(threads.deferToThread(
            _write_file_synchronously, source, fname,
        ))

        defer.returnValue(fname)

    @contextlib.contextmanager
    def store_into_file(self, file_info):
        """Context manager used to get a file like object to write into, as
        described by file_info.

        Actually yields a 3-tuple (file, fname, finish_cb), where finish_cb is a
        function that returns a Deferred that must be waited on after the file
        has been successfully written to.

        Args:
            file_info (FileInfo): Info about the file to store

        Example:

            with media_storage.store_into_file(info) as (f, fname, finish_cb):
                # .. write into f ...
                yield finish_cb()
        """

        path = self._file_info_to_path(file_info)
        fname = os.path.join(self.local_media_directory, path)

        dirname = os.path.dirname(fname)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        finished_called = [False]

        def finish():
            # This will be used later when we want to hit out to other storage
            # places
            finished_called[0] = True
            return defer.succeed(None)

        try:
            with open(fname, "wb") as f:
                yield f, fname, finish
        except Exception as e:
            try:
                os.remove(fname)
            except Exception:
                pass
            raise e

        if not finished_called:
            raise Exception("Fnished callback not called")

    @defer.inlineCallbacks
    def fetch_media(self, file_info):
        """Attempts to fetch media described by file_info from the local cache
        and configured storage providers.

        Args:
            file_info (FileInfo)

        Returns:
            Deferred(Responder): Returns a Responder if the file was found,
                otherwise None.
        """

        path = self._file_info_to_path(file_info)
        local_path = os.path.join(self.local_media_directory, path)
        if os.path.exists(local_path):
            defer.returnValue(FileResponder(open(local_path, "rb")))

        defer.returnValue(None)

    def _file_info_to_path(self, file_info):
        """Converts file_info into a relative path.
        """
        if file_info.url_cache:
            return self.filepaths.url_cache_filepath_rel(file_info.file_id)

        if file_info.server_name:
            if file_info.thumbnail:
                return self.filepaths.remote_media_thumbnail_rel(
                    server_name=file_info.server_name,
                    file_id=file_info.file_id,
                    width=file_info.thumbnail_width,
                    height=file_info.thumbnail_height,
                    content_type=file_info.thumbnail_type,
                    method=file_info.thumbnail_method
                )
            return self.filepaths.remote_media_filepath_rel(
                file_info.server_name, file_info.file_id,
            )

        if file_info.thumbnail:
            return self.filepaths.local_media_thumbnail_rel(
                media_id=file_info.file_id,
                width=file_info.thumbnail_width,
                height=file_info.thumbnail_height,
                content_type=file_info.thumbnail_type,
                method=file_info.thumbnail_method
            )
        return self.filepaths.local_media_filepath_rel(
            file_info.file_id,
        )


def _write_file_synchronously(source, fname):
    """Write `source` to the path `fname` synchronously. Should be called
    from a thread.

    Args:
        source: A file like object to be written
        fname (str): Path to write to
    """
    dirname = os.path.dirname(fname)
    if not os.path.exists(dirname):
        os.makedirs(dirname)

    source.seek(0)  # Ensure we read from the start of the file
    with open(fname, "wb") as f:
        shutil.copyfileobj(source, f)


class FileResponder(Responder):
    """Wraps an open file that can be sent to a request.

    Args:
        open_file (file): A file like object to be streamed ot the client,
            is closed when finished streaming.
    """
    def __init__(self, open_file):
        self.open_file = open_file

    @defer.inlineCallbacks
    def write_to_consumer(self, consumer):
        with self.open_file:
            yield FileSender().beginFileTransfer(self.open_file, consumer)

    def cancel(self):
        self.open_file.close()
