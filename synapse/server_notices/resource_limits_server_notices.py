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

from twisted.internet import defer

from synapse.api.errors import AuthError, SynapseError
from synapse.api.constants import EventTypes

logger = logging.getLogger(__name__)


class ResourceLimitsServerNotices(object):
    """
    """
    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer):
        """
        self._server_notices_manager = hs.get_server_notices_manager()
        self._store = hs.get_datastore()
        self.auth = hs.get_auth()
        self._server_notice_content = hs.config.user_consent_server_notice_content
        self._limit_usage_by_mau = hs.config.limit_usage_by_mau
        self._hs_disabled = hs.config.hs_disabled

        self._notified_of_blocking = set()
        self._resouce_limited = False
        self._message_handler = hs.get_message_handler()
        self._state = hs.get_state_handler()
        # Config checks?

    @defer.inlineCallbacks
    def maybe_send_server_notice_to_user(self, user_id):
        """Check if we need to send a notice to this user, and does so if so

        Args:
            user_id (str): user to check

        Returns:
            Deferred
        """
        if self._hs_disabled is True:
            return

        if self._limit_usage_by_mau is True:
            room_id = yield self._server_notices_manager.get_notice_room_for_user(user_id)


            # Alternate impl - currently inlcuded because I'm not sure I am on
            # the right track and want to share WIP

            # logger.info("GET STATE EVENTS")
            # currently_blocked = False
            # events = []
            # try:
            #     events = yield self._message_handler.get_state_events(user_id, room_id, types=[(EventTypes.Pinned, None)])
            # except AuthError as e:
            #     # The user has yet to join the server notices room
            #     pass
            #
            # pinned_event_refs = []
            # for e in events:
            #     logger.info('events %s' % e)
            #     logger.info(type(e))
            #     for key, event_ids in e['content'].items():
            #         logger.info('Key Event %s %s' % (key, event_ids))
            #         if key == 'pinned':
            #             pinned_event_refs = event_ids
            #
            # logger.info('pinned_event_refs %s' % pinned_event_refs)
            #
            # events = yield self._store.get_events(pinned_event_refs)
            # logger.info(events)
            # for event_id, event in events.items():
            #     logger.info("event_id, event event.type %s %s %s" % (event_id, event, event.type))
            #     if event.type == 'm.server_notice.usage_limit_reached':
            #         currently_blocked = True
            #
            # logger.info('Currently Blocked is %r' % currently_blocked)

            #for e in events:
            #    logger.info(e)
            currently_blocked = False
            logger.info("GET CURRENT STATE")
            pinned_state_event = yield self._state.get_current_state(room_id, event_type=EventTypes.Pinned)
            logger.info(events)
            logger.info(events.get('content'))

            referenced_events = []
            if pinned_state_event is not None:
                content = pinned_state_event.get('content')
                if content is not None:
                    referenced_events = content.get('pinned')

            events = yield self._store.get_events(referenced_events)
            logger.info(events)
            for event_id, event in events.items():
                logger.info("event_id, event event.type %s %s %s" % (event_id, event, event.type))
                if event.type == 'm.server_notice.usage_limit_reached':
                    currently_blocked = True

            logger.info("currently_blocked is %r" % currently_blocked)

                #event = yield self._store.get_event(events.event_id)
                #logger.info(event)

            #logger.info("GET CURRENT STATE IDs")
            #events = yield self._state.get_current_state_ids(room_id)
            #for k,v in events.items():
            #    logger.info('%s %s' % (k,v))

            timestamp = yield self._store.user_last_seen_monthly_active(user_id)
            if timestamp is None:
                # This user will be blocked from receiving the notice anyway.
                # In practice, not sure we can ever get here
                return
            try:
                # Normally should always pass in user_id if you have it, but in
                # this case are checking what would happen to other users if they
                # were to arrive.
                yield self.auth.check_auth_blocking()
                self._resouce_limited = False
                # Need to start removing notices
                # if user_id in self._notified_of_blocking:
                if currently_blocked:
                    # Send message to remove warning
                    # send state event here
                    # How do I do this? if drop the id, how to refer to it?
                    content = {
                        "pinned":[]
                    }
                    yield self._server_notices_manager.send_notice(
                        user_id, content, EventTypes.Pinned, '',
                    )
                    logger.info('deactivate block')

            except AuthError as e:
                # Need to start notifying of blocking
                try:
                    self._resouce_limited = True
                    #if user_id not in self._notified_of_blocking:
                    if not currently_blocked:
                        # TODO use admin email contained in error once PR lands
                        content = {
                            'body': e.msg,
                            'admin_email': 'stunt@adminemail.com',
                        }
                        event = yield self._server_notices_manager.send_notice(
                            user_id, content, EventTypes.ServerNoticeLimitReached
                        )

                        # send server notices state event here
                        # TODO Over writing pinned events
                        content = {
                            "pinned":[
                                event.event_id,
                            ]
                        }
                        logger.info("active block")
                        yield self._server_notices_manager.send_notice(
                            user_id, content, EventTypes.Pinned, '',
                        )

                except SynapseError as e:
                    logger.error("Error sending server notice about resource limits: %s", e)
