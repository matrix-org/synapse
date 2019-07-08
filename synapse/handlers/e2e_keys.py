# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from six import iteritems

from canonicaljson import encode_canonical_json, json
from signedjson.sign import SignatureVerifyException, verify_signed_json

from twisted.internet import defer

from synapse.api.errors import (
    CodeMessageException,
    Codes,
    FederationDeniedError,
    SynapseError,
)
from synapse.types import (
    UserID,
    get_domain_from_id,
    get_verify_key_from_cross_signing_key,
)
from synapse.util.async_helpers import Linearizer
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.logcontext import make_deferred_yieldable, run_in_background
from synapse.util.retryutils import NotRetryingDestination

logger = logging.getLogger(__name__)


class E2eKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.federation = hs.get_federation_client()
        self.device_handler = hs.get_device_handler()
        self.is_mine = hs.is_mine
        self.clock = hs.get_clock()

        # doesn't really work as part of the generic query API, because the
        # query request requires an object POST, but we abuse the
        # "query handler" interface.
        hs.get_federation_registry().register_query_handler(
            "client_keys", self.on_federation_query_client_keys
        )

    @defer.inlineCallbacks
    def query_devices(self, query_body, timeout, from_user_id=None):
        """ Handle a device key query from a client

        {
            "device_keys": {
                "<user_id>": ["<device_id>"]
            }
        }
        ->
        {
            "device_keys": {
                "<user_id>": {
                    "<device_id>": {
                        ...
                    }
                }
            }
        }

        Args:
            from_user_id (str): the user making the query.  This is used when
                adding cross-signing signatures to limit what signatures users
                can see.
        """
        device_keys_query = query_body.get("device_keys", {})

        # separate users by domain.
        # make a map from domain to user_id to device_ids
        local_query = {}
        remote_queries = {}

        for user_id, device_ids in device_keys_query.items():
            # we use UserID.from_string to catch invalid user ids
            if self.is_mine(UserID.from_string(user_id)):
                local_query[user_id] = device_ids
            else:
                remote_queries[user_id] = device_ids

        # First get local devices.
        failures = {}
        results = {}
        if local_query:
            local_result = yield self.query_local_devices(local_query)
            for user_id, keys in local_result.items():
                if user_id in local_query:
                    results[user_id] = keys

        # Now attempt to get any remote devices from our local cache.
        remote_queries_not_in_cache = {}
        if remote_queries:
            query_list = []
            for user_id, device_ids in iteritems(remote_queries):
                if device_ids:
                    query_list.extend((user_id, device_id) for device_id in device_ids)
                else:
                    query_list.append((user_id, None))

            user_ids_not_in_cache, remote_results = (
                yield self.store.get_user_devices_from_cache(
                    query_list
                )
            )
            for user_id, devices in iteritems(remote_results):
                user_devices = results.setdefault(user_id, {})
                for device_id, device in iteritems(devices):
                    keys = device.get("keys", None)
                    device_display_name = device.get("device_display_name", None)
                    if keys:
                        result = dict(keys)
                        unsigned = result.setdefault("unsigned", {})
                        if device_display_name:
                            unsigned["device_display_name"] = device_display_name
                        user_devices[device_id] = result

            for user_id in user_ids_not_in_cache:
                domain = get_domain_from_id(user_id)
                r = remote_queries_not_in_cache.setdefault(domain, {})
                r[user_id] = remote_queries[user_id]

        # Get cached cross-signing keys
        cross_signing_keys = yield self.query_cross_signing_keys(
            device_keys_query, from_user_id
        )

        # Now fetch any devices that we don't have in our cache
        @defer.inlineCallbacks
        def do_remote_query(destination):
            destination_query = remote_queries_not_in_cache[destination]
            try:
                remote_result = yield self.federation.query_client_keys(
                    destination,
                    {"device_keys": destination_query},
                    timeout=timeout
                )

                for user_id, keys in remote_result["device_keys"].items():
                    if user_id in destination_query:
                        results[user_id] = keys

                for user_id, key in remote_result["master_keys"].items():
                    if user_id in destination_query:
                        cross_signing_keys["master"][user_id] = key

                for user_id, key in remote_result["self_signing_keys"].items():
                    if user_id in destination_query:
                        cross_signing_keys["self_signing"][user_id] = key

            except Exception as e:
                failures[destination] = _exception_to_failure(e)

        yield make_deferred_yieldable(defer.gatherResults([
            run_in_background(do_remote_query, destination)
            for destination in remote_queries_not_in_cache
        ], consumeErrors=True))

        ret = {
            "device_keys": results, "failures": failures,
        }

        for key, value in iteritems(cross_signing_keys):
            ret[key + "_keys"] = value

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def query_cross_signing_keys(self, query, from_user_id=None):
        """Get cross-signing keys for users

        Args:
            query (dict[string, *]): map from user_id.  This function only looks
                at the dict's keys, and the values are ignored, so the query
                format used for query_devices can be used.
            from_user_id (str): the user making the query.  This is used when
                adding cross-signing signatures to limit what signatures users
                can see.

        Returns:
            defer.Deferred: (resolves to dict[string, dict[string, dict]]): map from
                (master|self_signing) -> map from user_id -> master key
        """
        master_keys = {}
        self_signing_keys = {}
        user_signing_keys = {}

        @defer.inlineCallbacks
        def get_cross_signing_key(user_id):
            try:
                key = yield self.store.get_e2e_cross_signing_key(
                    user_id, "master", from_user_id
                )
                if key:
                    master_keys[user_id] = key
            except Exception:
                pass

            try:
                key = yield self.store.get_e2e_cross_signing_key(
                    user_id, "self_signing", from_user_id
                )
                if key:
                    self_signing_keys[user_id] = key
            except Exception:
                pass

            # users can see other users' master and self-signing keys, but can
            # only see their own user-signing keys
            if from_user_id == user_id:
                try:
                    key = yield self.store.get_e2e_cross_signing_key(
                        user_id, "user_signing", from_user_id
                    )
                    if key:
                        user_signing_keys[user_id] = key
                except Exception:
                    pass

        yield make_deferred_yieldable(defer.gatherResults([
            run_in_background(get_cross_signing_key, user_id)
            for user_id in query.keys()
        ]))

        defer.returnValue({
            "master": master_keys,
            "self_signing": self_signing_keys,
            "user_signing": user_signing_keys,
        })

    @defer.inlineCallbacks
    def query_local_devices(self, query):
        """Get E2E device keys for local users

        Args:
            query (dict[string, list[string]|None): map from user_id to a list
                 of devices to query (None for all devices)

        Returns:
            defer.Deferred: (resolves to dict[string, dict[string, dict]]):
                 map from user_id -> device_id -> device details
        """
        local_query = []

        result_dict = {}
        for user_id, device_ids in query.items():
            # we use UserID.from_string to catch invalid user ids
            if not self.is_mine(UserID.from_string(user_id)):
                logger.warning("Request for keys for non-local user %s",
                               user_id)
                raise SynapseError(400, "Not a user here")

            if not device_ids:
                local_query.append((user_id, None))
            else:
                for device_id in device_ids:
                    local_query.append((user_id, device_id))

            # make sure that each queried user appears in the result dict
            result_dict[user_id] = {}

        results = yield self.store.get_e2e_device_keys(local_query)

        # Build the result structure, un-jsonify the results, and add the
        # "unsigned" section
        for user_id, device_keys in results.items():
            for device_id, device_info in device_keys.items():
                r = dict(device_info["keys"])
                r["unsigned"] = {}
                display_name = device_info["device_display_name"]
                if display_name is not None:
                    r["unsigned"]["device_display_name"] = display_name
                result_dict[user_id][device_id] = r

        defer.returnValue(result_dict)

    @defer.inlineCallbacks
    def on_federation_query_client_keys(self, query_body):
        """ Handle a device key query from a federated server
        """
        device_keys_query = query_body.get("device_keys", {})
        res = yield self.query_local_devices(device_keys_query)
        defer.returnValue({"device_keys": res})

    @defer.inlineCallbacks
    def claim_one_time_keys(self, query, timeout):
        local_query = []
        remote_queries = {}

        for user_id, device_keys in query.get("one_time_keys", {}).items():
            # we use UserID.from_string to catch invalid user ids
            if self.is_mine(UserID.from_string(user_id)):
                for device_id, algorithm in device_keys.items():
                    local_query.append((user_id, device_id, algorithm))
            else:
                domain = get_domain_from_id(user_id)
                remote_queries.setdefault(domain, {})[user_id] = device_keys

        results = yield self.store.claim_e2e_one_time_keys(local_query)

        json_result = {}
        failures = {}
        for user_id, device_keys in results.items():
            for device_id, keys in device_keys.items():
                for key_id, json_bytes in keys.items():
                    json_result.setdefault(user_id, {})[device_id] = {
                        key_id: json.loads(json_bytes)
                    }

        @defer.inlineCallbacks
        def claim_client_keys(destination):
            device_keys = remote_queries[destination]
            try:
                remote_result = yield self.federation.claim_client_keys(
                    destination,
                    {"one_time_keys": device_keys},
                    timeout=timeout
                )
                for user_id, keys in remote_result["one_time_keys"].items():
                    if user_id in device_keys:
                        json_result[user_id] = keys
            except Exception as e:
                failures[destination] = _exception_to_failure(e)

        yield make_deferred_yieldable(defer.gatherResults([
            run_in_background(claim_client_keys, destination)
            for destination in remote_queries
        ], consumeErrors=True))

        logger.info(
            "Claimed one-time-keys: %s",
            ",".join((
                "%s for %s:%s" % (key_id, user_id, device_id)
                for user_id, user_keys in iteritems(json_result)
                for device_id, device_keys in iteritems(user_keys)
                for key_id, _ in iteritems(device_keys)
            )),
        )

        defer.returnValue({
            "one_time_keys": json_result,
            "failures": failures
        })

    @defer.inlineCallbacks
    def upload_keys_for_user(self, user_id, device_id, keys):
        time_now = self.clock.time_msec()

        # TODO: Validate the JSON to make sure it has the right keys.
        device_keys = keys.get("device_keys", None)
        if device_keys:
            logger.info(
                "Updating device_keys for device %r for user %s at %d",
                device_id, user_id, time_now
            )
            # TODO: Sign the JSON with the server key
            changed = yield self.store.set_e2e_device_keys(
                user_id, device_id, time_now, device_keys,
            )
            if changed:
                # Only notify about device updates *if* the keys actually changed
                yield self.device_handler.notify_device_update(user_id, [device_id])

        one_time_keys = keys.get("one_time_keys", None)
        if one_time_keys:
            yield self._upload_one_time_keys_for_user(
                user_id, device_id, time_now, one_time_keys,
            )

        # the device should have been registered already, but it may have been
        # deleted due to a race with a DELETE request. Or we may be using an
        # old access_token without an associated device_id. Either way, we
        # need to double-check the device is registered to avoid ending up with
        # keys without a corresponding device.
        yield self.device_handler.check_device_registered(user_id, device_id)

        result = yield self.store.count_e2e_one_time_keys(user_id, device_id)

        defer.returnValue({"one_time_key_counts": result})

    @defer.inlineCallbacks
    def _upload_one_time_keys_for_user(self, user_id, device_id, time_now,
                                       one_time_keys):
        logger.info(
            "Adding one_time_keys %r for device %r for user %r at %d",
            one_time_keys.keys(), device_id, user_id, time_now,
        )

        # make a list of (alg, id, key) tuples
        key_list = []
        for key_id, key_obj in one_time_keys.items():
            algorithm, key_id = key_id.split(":")
            key_list.append((
                algorithm, key_id, key_obj
            ))

        # First we check if we have already persisted any of the keys.
        existing_key_map = yield self.store.get_e2e_one_time_keys(
            user_id, device_id, [k_id for _, k_id, _ in key_list]
        )

        new_keys = []  # Keys that we need to insert. (alg, id, json) tuples.
        for algorithm, key_id, key in key_list:
            ex_json = existing_key_map.get((algorithm, key_id), None)
            if ex_json:
                if not _one_time_keys_match(ex_json, key):
                    raise SynapseError(
                        400,
                        ("One time key %s:%s already exists. "
                         "Old key: %s; new key: %r") %
                        (algorithm, key_id, ex_json, key)
                    )
            else:
                new_keys.append((
                    algorithm, key_id, encode_canonical_json(key).decode('ascii')))

        yield self.store.add_e2e_one_time_keys(
            user_id, device_id, time_now, new_keys
        )

    @defer.inlineCallbacks
    def upload_signing_keys_for_user(self, user_id, keys):
        """Upload signing keys for cross-signing

        Args:
            user_id (string): the user uploading the keys
            keys (dict[string, dict]): the signing keys
        """

        # if a master key is uploaded, then check it.  Otherwise, load the
        # stored master key, to check signatures on other keys
        if "master_key" in keys:
            master_key = keys["master_key"]

            _check_cross_signing_key(master_key, user_id, "master")
        else:
            master_key = yield self.store.get_e2e_cross_signing_key(user_id, "master")

        # if there is no master key, then we can't do anything, because all the
        # other cross-signing keys need to be signed by the master key
        if not master_key:
            raise SynapseError(
                400,
                "No master key available",
                Codes.MISSING_PARAM
            )

        master_key_id, master_verify_key = get_verify_key_from_cross_signing_key(
            master_key
        )

        # for the other cross-signing keys, make sure that they have valid
        # signatures from the master key
        if "self_signing_key" in keys:
            self_signing_key = keys["self_signing_key"]

            _check_cross_signing_key(
                self_signing_key, user_id, "self_signing", master_verify_key
            )

        if "user_signing_key" in keys:
            user_signing_key = keys["user_signing_key"]

            _check_cross_signing_key(
                user_signing_key, user_id, "user_signing", master_verify_key
            )

        # if everything checks out, then store the keys and send notifications
        deviceids = []
        if "master_key" in keys:
            yield self.store.set_e2e_cross_signing_key(
                user_id, "master", master_key
            )
            deviceids.append(master_verify_key.version)
        if "self_signing_key" in keys:
            yield self.store.set_e2e_cross_signing_key(
                user_id, "self_signing", self_signing_key
            )
            deviceids.append(
                get_verify_key_from_cross_signing_key(self_signing_key)[1].version
            )
        if "user_signing_key" in keys:
            yield self.store.set_e2e_cross_signing_key(
                user_id, "user_signing", user_signing_key
            )
            # the signature stream matches the semantics that we want for
            # user-signing key updates: only the user themselves is notified of
            # their own user-signing key updates
            yield self.device_handler.notify_user_signature_update(user_id, [user_id])

        # master key and self-signing key updates match the semantics of device
        # list updates: all users who share an encrypted room are notified
        if len(deviceids):
            yield self.device_handler.notify_device_update(user_id, deviceids)

        defer.returnValue({})



def _check_cross_signing_key(key, user_id, key_type, signing_key=None):
    """Check a cross-signing key uploaded by a user.  Performs some basic sanity
    checking, and ensures that it is signed, if a signature is required.

    Args:
        key (dict): the key data to verify
        user_id (str): the user whose key is being checked
        key_type (str): the type of key that the key should be
        signing_key (VerifyKey): (optional) the signing key that the key should
            be signed with.  If omitted, signatures will not be checked.
    """
    if "user_id" not in key or key["user_id"] != user_id \
       or "usage" not in key or key_type not in key["usage"]:
        raise SynapseError(
            400,
            ("Invalid %s key" % key_type),
            Codes.INVALID_PARAM
        )

    if signing_key:
        try:
            verify_signed_json(key, user_id, signing_key)
        except SignatureVerifyException:
            raise SynapseError(
                400,
                ("Invalid signature or %s key" % key_type),
                Codes.INVALID_SIGNATURE
            )

def _exception_to_failure(e):
    if isinstance(e, CodeMessageException):
        return {
            "status": e.code, "message": str(e),
        }

    if isinstance(e, NotRetryingDestination):
        return {
            "status": 503, "message": "Not ready for retry",
        }

    if isinstance(e, FederationDeniedError):
        return {
            "status": 403, "message": "Federation Denied",
        }

    # include ConnectionRefused and other errors
    #
    # Note that some Exceptions (notably twisted's ResponseFailed etc) don't
    # give a string for e.message, which json then fails to serialize.
    return {
        "status": 503, "message": str(e),
    }


def _one_time_keys_match(old_key_json, new_key):
    old_key = json.loads(old_key_json)

    # if either is a string rather than an object, they must match exactly
    if not isinstance(old_key, dict) or not isinstance(new_key, dict):
        return old_key == new_key

    # otherwise, we strip off the 'signatures' if any, because it's legitimate
    # for different upload attempts to have different signatures.
    old_key.pop("signatures", None)
    new_key_copy = dict(new_key)
    new_key_copy.pop("signatures", None)

    return old_key == new_key_copy
