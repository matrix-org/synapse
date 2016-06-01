# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.constants import EventTypes
from synapse.appservice import ApplicationService

import logging

logger = logging.getLogger(__name__)


def log_failure(failure):
    logger.error(
        "Application Services Failure",
        exc_info=(
            failure.type,
            failure.value,
            failure.getTracebackObject()
        )
    )


class ApplicationServicesHandler(object):

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.is_mine_id = hs.is_mine_id
        self.appservice_api = hs.get_application_service_api()
        self.scheduler = hs.get_application_service_scheduler()
        self.started_scheduler = False

    @defer.inlineCallbacks
    def notify_interested_services(self, event):
        """Notifies (pushes) all application services interested in this event.

        Pushing is done asynchronously, so this method won't block for any
        prolonged length of time.

        Args:
            event(Event): The event to push out to interested services.
        """
        # Gather interested services
        services = yield self._get_services_for_event(event)
        if len(services) == 0:
            return  # no services need notifying

        # Do we know this user exists? If not, poke the user query API for
        # all services which match that user regex. This needs to block as these
        # user queries need to be made BEFORE pushing the event.
        yield self._check_user_exists(event.sender)
        if event.type == EventTypes.Member:
            yield self._check_user_exists(event.state_key)

        if not self.started_scheduler:
            self.scheduler.start().addErrback(log_failure)
            self.started_scheduler = True

        # Fork off pushes to these services
        for service in services:
            self.scheduler.submit_event_for_as(service, event)

    @defer.inlineCallbacks
    def query_user_exists(self, user_id):
        """Check if any application service knows this user_id exists.

        Args:
            user_id(str): The user to query if they exist on any AS.
        Returns:
            True if this user exists on at least one application service.
        """
        user_query_services = yield self._get_services_for_user(
            user_id=user_id
        )
        for user_service in user_query_services:
            is_known_user = yield self.appservice_api.query_user(
                user_service, user_id
            )
            if is_known_user:
                defer.returnValue(True)
        defer.returnValue(False)

    @defer.inlineCallbacks
    def query_room_alias_exists(self, room_alias):
        """Check if an application service knows this room alias exists.

        Args:
            room_alias(RoomAlias): The room alias to query.
        Returns:
            namedtuple: with keys "room_id" and "servers" or None if no
            association can be found.
        """
        room_alias_str = room_alias.to_string()
        alias_query_services = yield self._get_services_for_event(
            event=None,
            restrict_to=ApplicationService.NS_ALIASES,
            alias_list=[room_alias_str]
        )
        for alias_service in alias_query_services:
            is_known_alias = yield self.appservice_api.query_alias(
                alias_service, room_alias_str
            )
            if is_known_alias:
                # the alias exists now so don't query more ASes.
                result = yield self.store.get_association_from_room_alias(
                    room_alias
                )
                defer.returnValue(result)

    @defer.inlineCallbacks
    def _get_services_for_event(self, event, restrict_to="", alias_list=None):
        """Retrieve a list of application services interested in this event.

        Args:
            event(Event): The event to check. Can be None if alias_list is not.
            restrict_to(str): The namespace to restrict regex tests to.
            alias_list: A list of aliases to get services for. If None, this
            list is obtained from the database.
        Returns:
            list<ApplicationService>: A list of services interested in this
            event based on the service regex.
        """
        member_list = None
        if hasattr(event, "room_id"):
            # We need to know the aliases associated with this event.room_id,
            # if any.
            if not alias_list:
                alias_list = yield self.store.get_aliases_for_room(
                    event.room_id
                )
            # We need to know the members associated with this event.room_id,
            # if any.
            member_list = yield self.store.get_users_in_room(event.room_id)

        services = yield self.store.get_app_services()
        interested_list = [
            s for s in services if (
                s.is_interested(event, restrict_to, alias_list, member_list)
            )
        ]
        defer.returnValue(interested_list)

    @defer.inlineCallbacks
    def _get_services_for_user(self, user_id):
        services = yield self.store.get_app_services()
        interested_list = [
            s for s in services if (
                s.is_interested_in_user(user_id)
            )
        ]
        defer.returnValue(interested_list)

    @defer.inlineCallbacks
    def _is_unknown_user(self, user_id):
        if not self.is_mine_id(user_id):
            # we don't know if they are unknown or not since it isn't one of our
            # users. We can't poke ASes.
            defer.returnValue(False)
            return

        user_info = yield self.store.get_user_by_id(user_id)
        if user_info:
            defer.returnValue(False)
            return

        # user not found; could be the AS though, so check.
        services = yield self.store.get_app_services()
        service_list = [s for s in services if s.sender == user_id]
        defer.returnValue(len(service_list) == 0)

    @defer.inlineCallbacks
    def _check_user_exists(self, user_id):
        unknown_user = yield self._is_unknown_user(user_id)
        if unknown_user:
            exists = yield self.query_user_exists(user_id)
            defer.returnValue(exists)
        defer.returnValue(True)
