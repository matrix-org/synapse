# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.api.errors import StoreError

from ._base import SQLBaseStore


# XXX: This feels like it should belong in a "models" module, not storage.
class ApplicationService(object):
    """Defines an application service.

    Provides methods to check if this service is "interested" in events.
    """

    def __init__(self, token, url=None, namespaces=None):
        self.token = token
        if url:
            self.url = url
        if namespaces:
            self.namespaces = namespaces

    def is_interested(self, event):
        """Check if this service is interested in this event.

        Args:
            event(Event): The event to check.
        Returns:
            bool: True if this service would like to know about this event.
        """
        # NB: This does not check room alias regex matches because that requires
        # more context that an Event can provide. Room alias matches are checked
        # in the ApplicationServiceHandler.

        # TODO check if event.room_id regex matches
        # TODO check if event.user_id regex matches (or m.room.member state_key)

        return True


class ApplicationServiceCache(object):
    """Caches ApplicationServices and provides utility functions on top.

    This class is designed to be invoked on incoming events in order to avoid
    hammering the database every time to extract a list of application service
    regexes.
    """

    def __init__(self):
        self.services = []

    def get_services_for_event(self, event):
        """Retrieve a list of application services interested in this event.

        Args:
            event(Event): The event to check.
        Returns:
            list<ApplicationService>: A list of services interested in this
            event based on the service regex.
        """
        interested_list = [
            s for s in self.services if s.is_event_claimed(event)
        ]
        return interested_list


class ApplicationServiceStore(SQLBaseStore):

    def __init__(self, hs):
        super(ApplicationServiceStore, self).__init__(hs)
        self.cache = ApplicationServiceCache()
        self.clock = hs.get_clock()
        self._populate_cache()

    def unregister_app_service(self, token):
        """Unregisters this service.

        This removes all AS specific regex and the base URL. The token is the
        only thing preserved for future registration attempts.
        """
        # TODO: DELETE FROM application_services_regex WHERE id=this service
        # TODO: SET url=NULL WHERE token=token
        # TODO: Update cache
        pass

    def update_app_service(self, service):
        """Update an application service, clobbering what was previously there.

        Args:
            service(ApplicationService): The updated service.
        """
        # NB: There is no "insert" since we provide no public-facing API to
        # allocate new ASes. It relies on the server admin inserting the AS
        # token into the database manually.

        # TODO: UPDATE application_services, SET url WHERE token=service.token
        # TODO: DELETE FROM application_services_regex WHERE id=this service
        # TODO: INSERT INTO application_services_regex <new namespace regex>
        # TODO: Update cache
        pass

    def get_services_for_event(self, event):
        return self.cache.get_services_for_event(event)

    @defer.inlineCallbacks
    def get_app_service(self, as_token, from_cache=True):
        """Get the application service with the given token.

        Args:
            token (str): The application service token.
            from_cache (bool): True to get this service from the cache, False to
                               check the database.
        Raises:
            StoreError if there was a problem retrieving this service.
        """

        if from_cache:
            for service in self.cache.services:
                if service.token == as_token:
                    defer.returnValue(service)
                    return
            defer.returnValue(None)
            return


        # TODO: This should be JOINed with the application_services_regex table.
        row = self._simple_select_one(
            "application_services", {"token": as_token},
            ["url", "token"]
        )
        if not row:
            raise StoreError(400, "Bad application services token supplied.")
        defer.returnValue(row)

    def _populate_cache(self):
        """Populates the ApplicationServiceCache from the database."""
        pass
