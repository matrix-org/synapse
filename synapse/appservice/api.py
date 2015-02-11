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

from synapse.api.errors import CodeMessageException
from synapse.http.client import SimpleHttpClient
from synapse.events.utils import serialize_event

import logging
import urllib

logger = logging.getLogger(__name__)


class ApplicationServiceApi(SimpleHttpClient):
    """This class manages HS -> AS communications, including querying and
    pushing.
    """

    def __init__(self,  hs):
        super(ApplicationServiceApi, self).__init__(hs)
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def query_user(self, service, user_id):
        uri = service.url + ("/users/%s" % urllib.quote(user_id))
        response = None
        try:
            response = yield self.get_json(uri, {
                "access_token": service.hs_token
            })
            if response is not None:  # just an empty json object
                defer.returnValue(True)
        except CodeMessageException as e:
            if e.code == 404:
                defer.returnValue(False)
                return
            logger.warning("query_user to %s received %s", uri, e.code)
        except Exception as ex:
            logger.warning("query_user to %s threw exception %s", uri, ex)
        defer.returnValue(False)

    @defer.inlineCallbacks
    def query_alias(self, service, alias):
        uri = service.url + ("/rooms/%s" % urllib.quote(alias))
        response = None
        try:
            response = yield self.get_json(uri, {
                "access_token": service.hs_token
            })
            if response is not None:  # just an empty json object
                defer.returnValue(True)
        except CodeMessageException as e:
            logger.warning("query_alias to %s received %s", uri, e.code)
            if e.code == 404:
                defer.returnValue(False)
                return
        except Exception as ex:
            logger.warning("query_alias to %s threw exception %s", uri, ex)
        defer.returnValue(False)

    @defer.inlineCallbacks
    def push_bulk(self, service, events):
        events = self._serialize(events)

        uri = service.url + ("/transactions/%s" %
                             urllib.quote(str(0)))  # TODO txn_ids
        response = None
        try:
            response = yield self.put_json(
                uri=uri,
                json_body={
                    "events": events
                },
                args={
                    "access_token": service.hs_token
                })
            if response:  # just an empty json object
                # TODO: Mark txn as sent successfully
                defer.returnValue(True)
        except CodeMessageException as e:
            logger.warning("push_bulk to %s received %s", uri, e.code)
        except Exception as ex:
            logger.warning("push_bulk to %s threw exception %s", uri, ex)
        defer.returnValue(False)

    @defer.inlineCallbacks
    def push(self, service, event):
        response = yield self.push_bulk(service, [event])
        defer.returnValue(response)

    def _serialize(self, events):
        time_now = self.clock.time_msec()
        return [
            serialize_event(e, time_now, as_client_event=True) for e in events
        ]
