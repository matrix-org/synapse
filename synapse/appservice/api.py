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
import logging

from six.moves import urllib

from prometheus_client import Counter

from twisted.internet import defer

from synapse.api.constants import ThirdPartyEntityKind
from synapse.api.errors import CodeMessageException
from synapse.events.utils import serialize_event
from synapse.http.client import SimpleHttpClient
from synapse.types import ThirdPartyInstanceID
from synapse.util.caches.response_cache import ResponseCache

logger = logging.getLogger(__name__)

sent_transactions_counter = Counter(
    "synapse_appservice_api_sent_transactions",
    "Number of /transactions/ requests sent",
    ["service"]
)

failed_transactions_counter = Counter(
    "synapse_appservice_api_failed_transactions",
    "Number of /transactions/ requests that failed to send",
    ["service"]
)

sent_events_counter = Counter(
    "synapse_appservice_api_sent_events",
    "Number of events sent to the AS",
    ["service"]
)

HOUR_IN_MS = 60 * 60 * 1000


APP_SERVICE_PREFIX = "/_matrix/app/unstable"


def _is_valid_3pe_metadata(info):
    if "instances" not in info:
        return False
    if not isinstance(info["instances"], list):
        return False
    return True


def _is_valid_3pe_result(r, field):
    if not isinstance(r, dict):
        return False

    for k in (field, "protocol"):
        if k not in r:
            return False
        if not isinstance(r[k], str):
            return False

    if "fields" not in r:
        return False
    fields = r["fields"]
    if not isinstance(fields, dict):
        return False
    for k in fields.keys():
        if not isinstance(fields[k], str):
            return False

    return True


class ApplicationServiceApi(SimpleHttpClient):
    """This class manages HS -> AS communications, including querying and
    pushing.
    """

    def __init__(self, hs):
        super(ApplicationServiceApi, self).__init__(hs)
        self.clock = hs.get_clock()

        self.protocol_meta_cache = ResponseCache(hs, "as_protocol_meta",
                                                 timeout_ms=HOUR_IN_MS)

    @defer.inlineCallbacks
    def query_user(self, service, user_id):
        if service.url is None:
            defer.returnValue(False)
        uri = service.url + ("/users/%s" % urllib.parse.quote(user_id))
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
        if service.url is None:
            defer.returnValue(False)
        uri = service.url + ("/rooms/%s" % urllib.parse.quote(alias))
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
    def query_3pe(self, service, kind, protocol, fields):
        if kind == ThirdPartyEntityKind.USER:
            required_field = "userid"
        elif kind == ThirdPartyEntityKind.LOCATION:
            required_field = "alias"
        else:
            raise ValueError(
                "Unrecognised 'kind' argument %r to query_3pe()", kind
            )
        if service.url is None:
            defer.returnValue([])

        uri = "%s%s/thirdparty/%s/%s" % (
            service.url,
            APP_SERVICE_PREFIX,
            kind,
            urllib.parse.quote(protocol)
        )
        try:
            response = yield self.get_json(uri, fields)
            if not isinstance(response, list):
                logger.warning(
                    "query_3pe to %s returned an invalid response %r",
                    uri, response
                )
                defer.returnValue([])

            ret = []
            for r in response:
                if _is_valid_3pe_result(r, field=required_field):
                    ret.append(r)
                else:
                    logger.warning(
                        "query_3pe to %s returned an invalid result %r",
                        uri, r
                    )

            defer.returnValue(ret)
        except Exception as ex:
            logger.warning("query_3pe to %s threw exception %s", uri, ex)
            defer.returnValue([])

    def get_3pe_protocol(self, service, protocol):
        if service.url is None:
            defer.returnValue({})

        @defer.inlineCallbacks
        def _get():
            uri = "%s%s/thirdparty/protocol/%s" % (
                service.url,
                APP_SERVICE_PREFIX,
                urllib.parse.quote(protocol)
            )
            try:
                info = yield self.get_json(uri, {})

                if not _is_valid_3pe_metadata(info):
                    logger.warning("query_3pe_protocol to %s did not return a"
                                   " valid result", uri)
                    defer.returnValue(None)

                for instance in info.get("instances", []):
                    network_id = instance.get("network_id", None)
                    if network_id is not None:
                        instance["instance_id"] = ThirdPartyInstanceID(
                            service.id, network_id,
                        ).to_string()

                defer.returnValue(info)
            except Exception as ex:
                logger.warning("query_3pe_protocol to %s threw exception %s",
                               uri, ex)
                defer.returnValue(None)

        key = (service.id, protocol)
        return self.protocol_meta_cache.wrap(key, _get)

    @defer.inlineCallbacks
    def push_bulk(self, service, events, txn_id=None):
        if service.url is None:
            defer.returnValue(True)

        events = self._serialize(events)

        if txn_id is None:
            logger.warning("push_bulk: Missing txn ID sending events to %s",
                           service.url)
            txn_id = str(0)
        txn_id = str(txn_id)

        uri = service.url + ("/transactions/%s" %
                             urllib.parse.quote(txn_id))
        try:
            yield self.put_json(
                uri=uri,
                json_body={
                    "events": events
                },
                args={
                    "access_token": service.hs_token
                })
            sent_transactions_counter.labels(service.id).inc()
            sent_events_counter.labels(service.id).inc(len(events))
            defer.returnValue(True)
            return
        except CodeMessageException as e:
            logger.warning("push_bulk to %s received %s", uri, e.code)
        except Exception as ex:
            logger.warning("push_bulk to %s threw exception %s", uri, ex)
        failed_transactions_counter.labels(service.id).inc()
        defer.returnValue(False)

    def _serialize(self, events):
        time_now = self.clock.time_msec()
        return [
            serialize_event(e, time_now, as_client_event=True) for e in events
        ]
