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
import logging
import re
from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.errors import StoreError
from ._base import SQLBaseStore


logger = logging.getLogger(__name__)

namespace_enum = [
    "users",    # 0
    "aliases",  # 1
    "rooms"   # 2
]


# XXX: This feels like it should belong in a "models" module, not storage.
class ApplicationService(object):
    """Defines an application service.

    Provides methods to check if this service is "interested" in events.
    """

    def __init__(self, token, url=None, namespaces=None):
        self.token = token
        self.url = url
        self.namespaces = self._check_namespaces(namespaces)

    def _check_namespaces(self, namespaces):
        # Sanity check that it is of the form:
        # {
        #   users: ["regex",...],
        #   aliases: ["regex",...],
        #   rooms: ["regex",...],
        # }
        if not namespaces:
            return None

        for ns in ["users", "rooms", "aliases"]:
            if type(namespaces[ns]) != list:
                raise ValueError("Bad namespace value for '%s'", ns)
            for regex in namespaces[ns]:
                if not isinstance(regex, basestring):
                    raise ValueError("Expected string regex for ns '%s'", ns)
        return namespaces

    def _matches_regex(self, test_string, namespace_key):
        for regex in self.namespaces[namespace_key]:
            if re.match(regex, test_string):
                return True
        return False

    def _matches_user(self, event):
        if (hasattr(event, "user_id") and
                self._matches_regex(event.user_id, "users")):
            return True
        # also check m.room.member state key
        if (hasattr(event, "type") and event.type == EventTypes.Member
                and hasattr(event, "state_key")
                and self._matches_regex(event.state_key, "users")):
            return True
        return False

    def _matches_room_id(self, event):
        if hasattr(event, "room_id"):
            return self._matches_regex(event.room_id, "rooms")
        return False

    def _matches_aliases(self, event, alias_list):
        for alias in alias_list:
            if self._matches_regex(alias, "aliases"):
                return True
        return False

    def is_interested(self, event, aliases_for_event=None):
        """Check if this service is interested in this event.

        Args:
            event(Event): The event to check.
            aliases_for_event(list): A list of all the known room aliases for
            this event.
        Returns:
            bool: True if this service would like to know about this event.
        """
        if aliases_for_event is None:
            aliases_for_event = []

        return (self._matches_user(event)
                or self._matches_aliases(event, aliases_for_event)
                or self._matches_room_id(event))

    def __str__(self):
        return "ApplicationService: %s" % (self.__dict__,)


class ApplicationServiceCache(object):
    """Caches ApplicationServices and provides utility functions on top.

    This class is designed to be invoked on incoming events in order to avoid
    hammering the database every time to extract a list of application service
    regexes.
    """

    def __init__(self):
        self.services = []


class ApplicationServiceStore(SQLBaseStore):

    def __init__(self, hs):
        super(ApplicationServiceStore, self).__init__(hs)
        self.cache = ApplicationServiceCache()
        self._populate_cache()

    @defer.inlineCallbacks
    def unregister_app_service(self, token):
        """Unregisters this service.

        This removes all AS specific regex and the base URL. The token is the
        only thing preserved for future registration attempts.
        """
        yield self.runInteraction(
            "unregister_app_service",
            self._unregister_app_service_txn,
            token,
        )
        # update cache TODO: Should this be in the txn?
        for service in self.cache.services:
            if service.token == token:
                service.url = None
                service.namespaces = None

    def _unregister_app_service_txn(self, txn, token):
        # kill the url to prevent pushes
        txn.execute(
            "UPDATE application_services SET url=NULL WHERE token=?",
            (token,)
        )

        # cleanup regex
        as_id = self._get_as_id_txn(txn, token)
        if not as_id:
            logger.warning(
                "unregister_app_service_txn: Failed to find as_id for token=",
                token
            )
            return False

        txn.execute(
            "DELETE FROM application_services_regex WHERE as_id=?",
            (as_id,)
        )
        return True

    @defer.inlineCallbacks
    def update_app_service(self, service):
        """Update an application service, clobbering what was previously there.

        Args:
            service(ApplicationService): The updated service.
        """
        # NB: There is no "insert" since we provide no public-facing API to
        # allocate new ASes. It relies on the server admin inserting the AS
        # token into the database manually.
        if not service.token or not service.url:
            raise StoreError(400, "Token and url must be specified.")

        yield self.runInteraction(
            "update_app_service",
            self._update_app_service_txn,
            service
        )

        # update cache TODO: Should this be in the txn?
        for (index, cache_service) in enumerate(self.cache.services):
            if service.token == cache_service.token:
                self.cache.services[index] = service
                logger.info("Updated: %s", service)
                return
        # new entry
        self.cache.services.append(service)
        logger.info("Updated(new): %s", service)

    def _update_app_service_txn(self, txn, service):
        as_id = self._get_as_id_txn(txn, service.token)
        if not as_id:
            logger.warning(
                "update_app_service_txn: Failed to find as_id for token=",
                service.token
            )
            return False

        txn.execute(
            "UPDATE application_services SET url=? WHERE id=?",
            (service.url, as_id,)
        )
        # cleanup regex
        txn.execute(
            "DELETE FROM application_services_regex WHERE id=?",
            (as_id,)
        )
        for (ns_int, ns_str) in enumerate(namespace_enum):
            if ns_str in service.namespaces:
                for regex in service.namespaces[ns_str]:
                    txn.execute(
                        "INSERT INTO application_services_regex("
                        "as_id, namespace, regex) values(?,?,?)",
                        (as_id, ns_int, regex)
                    )
        return True

    def _get_as_id_txn(self, txn, token):
        cursor = txn.execute(
            "SELECT id FROM application_services WHERE token=?",
            (token,)
        )
        res = cursor.fetchone()
        if res:
            return res[0]

    def get_app_services(self):
        return self.cache.services

    def get_app_service_by_token(self, token, from_cache=True):
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
                if service.token == token:
                    return service
            return None

        # TODO: The from_cache=False impl
        # TODO: This should be JOINed with the application_services_regex table.


    @defer.inlineCallbacks
    def _populate_cache(self):
        """Populates the ApplicationServiceCache from the database."""
        sql = ("SELECT * FROM application_services LEFT JOIN "
               "application_services_regex ON application_services.id = "
               "application_services_regex.as_id")
        # SQL results in the form:
        # [
        #   {
        #     'regex': "something",
        #     'url': "something",
        #     'namespace': enum,
        #     'as_id': 0,
        #     'token': "something",
        #     'id': 0
        #   }
        # ]
        services = {}
        results = yield self._execute_and_decode(sql)
        for res in results:
            as_token = res["token"]
            if as_token not in services:
                # add the service
                services[as_token] = {
                    "url": res["url"],
                    "token": as_token,
                    "namespaces": {
                        "users": [],
                        "aliases": [],
                        "rooms": []
                    }
                }
            # add the namespace regex if one exists
            ns_int = res["namespace"]
            if ns_int is None:
                continue
            try:
                services[as_token]["namespaces"][namespace_enum[ns_int]].append(
                    res["regex"]
                )
            except IndexError:
                logger.error("Bad namespace enum '%s'. %s", ns_int, res)

        for service in services.values():
            logger.info("Found application service: %s", service)
            self.cache.services.append(ApplicationService(
                service["token"],
                service["url"],
                service["namespaces"]
            ))

