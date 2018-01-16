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

from twisted.internet import defer, threads

from .media_storage import FileResponder

from synapse.util.logcontext import preserve_fn

import logging
import os
import shutil


logger = logging.getLogger(__name__)


class StorageProvider(object):
    """A storage provider is a service that can store uploaded media and
    retrieve them.
    """
    def store_file(self, path, file_info):
        """Store the file described by file_info. The actual contents can be
        retrieved by reading the file in file_info.upload_path.

        Args:
            path (str): Relative path of file in local cache
            file_info (FileInfo)

        Returns:
            Deferred
        """
        pass

    def fetch(self, path, file_info):
        """Attempt to fetch the file described by file_info and stream it
        into writer.

        Args:
            path (str): Relative path of file in local cache
            file_info (FileInfo)

        Returns:
            Deferred(Responder): Returns a Responder if the provider has the file,
                otherwise returns None.
        """
        pass


class StorageProviderWrapper(StorageProvider):
    """Wraps a storage provider and provides various config options

    Args:
        backend (StorageProvider)
        store (bool): Whether to store new files or not.
        store_synchronous (bool): Whether to wait for file to be successfully
            uploaded, or todo the upload in the backgroud.
        store_remote (bool): Whether remote media should be uploaded
    """
    def __init__(self, backend, store, store_synchronous, store_remote):
        self.backend = backend
        self.store = store
        self.store_synchronous = store_synchronous
        self.store_remote = store_remote

    def store_file(self, path, file_info):
        if not self.store:
            return defer.succeed(None)

        if file_info.server_name and not self.store_remote:
            return defer.succeed(None)

        if self.store_synchronous:
            return self.backend.store_file(path, file_info)
        else:
            # TODO: Handle errors.
            preserve_fn(self.backend.store_file)(path, file_info)
            return defer.succeed(None)

    def fetch(self, path, file_info):
        return self.backend.fetch(path, file_info)


class FileStorageProviderBackend(StorageProvider):
    """A storage provider that stores files in a directory on a filesystem.

    Args:
        cache_directory (str): Base path of the local media repository
        base_directory (str): Base path to store new files
    """

    def __init__(self, cache_directory, base_directory):
        self.cache_directory = cache_directory
        self.base_directory = base_directory

    def store_file(self, path, file_info):
        """See StorageProvider.store_file"""

        primary_fname = os.path.join(self.cache_directory, path)
        backup_fname = os.path.join(self.base_directory, path)

        dirname = os.path.dirname(backup_fname)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        return threads.deferToThread(
            shutil.copyfile, primary_fname, backup_fname,
        )

    def fetch(self, path, file_info):
        """See StorageProvider.fetch"""

        backup_fname = os.path.join(self.base_directory, path)
        if os.path.isfile(backup_fname):
            return FileResponder(open(backup_fname, "rb"))
