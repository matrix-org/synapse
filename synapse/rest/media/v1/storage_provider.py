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
import os
import shutil

from twisted.internet import defer

from synapse.config._base import Config
from synapse.util import logcontext
from synapse.util.logcontext import run_in_background

from .media_storage import FileResponder

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
        store_local (bool): Whether to store new local files or not.
        store_synchronous (bool): Whether to wait for file to be successfully
            uploaded, or todo the upload in the backgroud.
        store_remote (bool): Whether remote media should be uploaded
    """

    def __init__(self, backend, store_local, store_synchronous, store_remote):
        self.backend = backend
        self.store_local = store_local
        self.store_synchronous = store_synchronous
        self.store_remote = store_remote

    def store_file(self, path, file_info):
        if not file_info.server_name and not self.store_local:
            return defer.succeed(None)

        if file_info.server_name and not self.store_remote:
            return defer.succeed(None)

        if self.store_synchronous:
            return self.backend.store_file(path, file_info)
        else:
            # TODO: Handle errors.
            def store():
                try:
                    return self.backend.store_file(path, file_info)
                except Exception:
                    logger.exception("Error storing file")

            run_in_background(store)
            return defer.succeed(None)

    def fetch(self, path, file_info):
        return self.backend.fetch(path, file_info)


class FileStorageProviderBackend(StorageProvider):
    """A storage provider that stores files in a directory on a filesystem.

    Args:
        hs (HomeServer)
        config: The config returned by `parse_config`.
    """

    def __init__(self, hs, config):
        self.hs = hs
        self.cache_directory = hs.config.media_store_path
        self.base_directory = config

    def store_file(self, path, file_info):
        """See StorageProvider.store_file"""

        primary_fname = os.path.join(self.cache_directory, path)
        backup_fname = os.path.join(self.base_directory, path)

        dirname = os.path.dirname(backup_fname)
        if not os.path.exists(dirname):
            os.makedirs(dirname)

        return logcontext.defer_to_thread(
            self.hs.get_reactor(), shutil.copyfile, primary_fname, backup_fname
        )

    def fetch(self, path, file_info):
        """See StorageProvider.fetch"""

        backup_fname = os.path.join(self.base_directory, path)
        if os.path.isfile(backup_fname):
            return FileResponder(open(backup_fname, "rb"))

    @staticmethod
    def parse_config(config):
        """Called on startup to parse config supplied. This should parse
        the config and raise if there is a problem.

        The returned value is passed into the constructor.

        In this case we only care about a single param, the directory, so let's
        just pull that out.
        """
        return Config.ensure_directory(config["directory"])
