# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017, 2018 New Vector Ltd
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
from collections import namedtuple

import six
from six import raise_from
from six.moves import urllib

from signedjson.key import (
    decode_verify_key_bytes,
    encode_verify_key_base64,
    is_signing_algorithm_supported,
)
from signedjson.sign import (
    SignatureVerifyException,
    encode_canonical_json,
    sign_json,
    signature_ids,
    verify_signed_json,
)
from unpaddedbase64 import decode_base64

from twisted.internet import defer

from synapse.api.errors import (
    Codes,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.storage.keys import FetchKeyResult
from synapse.util import logcontext, unwrapFirstError
from synapse.util.logcontext import (
    LoggingContext,
    PreserveLoggingContext,
    preserve_fn,
    run_in_background,
)
from synapse.util.metrics import Measure
from synapse.util.retryutils import NotRetryingDestination

logger = logging.getLogger(__name__)


VerifyKeyRequest = namedtuple(
    "VerifyRequest", ("server_name", "key_ids", "json_object", "deferred")
)
"""
A request for a verify key to verify a JSON object.

Attributes:
    server_name(str): The name of the server to verify against.
    key_ids(set(str)): The set of key_ids to that could be used to verify the
        JSON object
    json_object(dict): The JSON object to verify.
    deferred(Deferred[str, str, nacl.signing.VerifyKey]):
        A deferred (server_name, key_id, verify_key) tuple that resolves when
        a verify key has been fetched. The deferreds' callbacks are run with no
        logcontext.
"""


class KeyLookupError(ValueError):
    pass


class Keyring(object):
    def __init__(self, hs):
        self.clock = hs.get_clock()

        self._key_fetchers = (
            StoreKeyFetcher(hs),
            PerspectivesKeyFetcher(hs),
            ServerKeyFetcher(hs),
        )

        # map from server name to Deferred. Has an entry for each server with
        # an ongoing key download; the Deferred completes once the download
        # completes.
        #
        # These are regular, logcontext-agnostic Deferreds.
        self.key_downloads = {}

    def verify_json_for_server(self, server_name, json_object):
        return logcontext.make_deferred_yieldable(
            self.verify_json_objects_for_server([(server_name, json_object)])[0]
        )

    def verify_json_objects_for_server(self, server_and_json):
        """Bulk verifies signatures of json objects, bulk fetching keys as
        necessary.

        Args:
            server_and_json (list): List of pairs of (server_name, json_object)

        Returns:
            List<Deferred>: for each input pair, a deferred indicating success
                or failure to verify each json object's signature for the given
                server_name. The deferreds run their callbacks in the sentinel
                logcontext.
        """
        # a list of VerifyKeyRequests
        verify_requests = []
        handle = preserve_fn(_handle_key_deferred)

        def process(server_name, json_object):
            """Process an entry in the request list

            Given a (server_name, json_object) pair from the request list,
            adds a key request to verify_requests, and returns a deferred which will
            complete or fail (in the sentinel context) when verification completes.
            """
            key_ids = signature_ids(json_object, server_name)

            if not key_ids:
                return defer.fail(
                    SynapseError(
                        400, "Not signed by %s" % (server_name,), Codes.UNAUTHORIZED
                    )
                )

            logger.debug("Verifying for %s with key_ids %s", server_name, key_ids)

            # add the key request to the queue, but don't start it off yet.
            verify_request = VerifyKeyRequest(
                server_name, key_ids, json_object, defer.Deferred()
            )
            verify_requests.append(verify_request)

            # now run _handle_key_deferred, which will wait for the key request
            # to complete and then do the verification.
            #
            # We want _handle_key_request to log to the right context, so we
            # wrap it with preserve_fn (aka run_in_background)
            return handle(verify_request)

        results = [
            process(server_name, json_object)
            for server_name, json_object in server_and_json
        ]

        if verify_requests:
            run_in_background(self._start_key_lookups, verify_requests)

        return results

    @defer.inlineCallbacks
    def _start_key_lookups(self, verify_requests):
        """Sets off the key fetches for each verify request

        Once each fetch completes, verify_request.deferred will be resolved.

        Args:
            verify_requests (List[VerifyKeyRequest]):
        """

        try:
            # create a deferred for each server we're going to look up the keys
            # for; we'll resolve them once we have completed our lookups.
            # These will be passed into wait_for_previous_lookups to block
            # any other lookups until we have finished.
            # The deferreds are called with no logcontext.
            server_to_deferred = {
                rq.server_name: defer.Deferred() for rq in verify_requests
            }

            # We want to wait for any previous lookups to complete before
            # proceeding.
            yield self.wait_for_previous_lookups(server_to_deferred)

            # Actually start fetching keys.
            self._get_server_verify_keys(verify_requests)

            # When we've finished fetching all the keys for a given server_name,
            # resolve the deferred passed to `wait_for_previous_lookups` so that
            # any lookups waiting will proceed.
            #
            # map from server name to a set of request ids
            server_to_request_ids = {}

            for verify_request in verify_requests:
                server_name = verify_request.server_name
                request_id = id(verify_request)
                server_to_request_ids.setdefault(server_name, set()).add(request_id)

            def remove_deferreds(res, verify_request):
                server_name = verify_request.server_name
                request_id = id(verify_request)
                server_to_request_ids[server_name].discard(request_id)
                if not server_to_request_ids[server_name]:
                    d = server_to_deferred.pop(server_name, None)
                    if d:
                        d.callback(None)
                return res

            for verify_request in verify_requests:
                verify_request.deferred.addBoth(remove_deferreds, verify_request)
        except Exception:
            logger.exception("Error starting key lookups")

    @defer.inlineCallbacks
    def wait_for_previous_lookups(self, server_to_deferred):
        """Waits for any previous key lookups for the given servers to finish.

        Args:
            server_to_deferred (dict[str, Deferred]): server_name to deferred which gets
                resolved once we've finished looking up keys for that server.
                The Deferreds should be regular twisted ones which call their
                callbacks with no logcontext.

        Returns: a Deferred which resolves once all key lookups for the given
            servers have completed. Follows the synapse rules of logcontext
            preservation.
        """
        loop_count = 1
        while True:
            wait_on = [
                (server_name, self.key_downloads[server_name])
                for server_name in server_to_deferred.keys()
                if server_name in self.key_downloads
            ]
            if not wait_on:
                break
            logger.info(
                "Waiting for existing lookups for %s to complete [loop %i]",
                [w[0] for w in wait_on],
                loop_count,
            )
            with PreserveLoggingContext():
                yield defer.DeferredList((w[1] for w in wait_on))

            loop_count += 1

        ctx = LoggingContext.current_context()

        def rm(r, server_name_):
            with PreserveLoggingContext(ctx):
                logger.debug("Releasing key lookup lock on %s", server_name_)
                self.key_downloads.pop(server_name_, None)
            return r

        for server_name, deferred in server_to_deferred.items():
            logger.debug("Got key lookup lock on %s", server_name)
            self.key_downloads[server_name] = deferred
            deferred.addBoth(rm, server_name)

    def _get_server_verify_keys(self, verify_requests):
        """Tries to find at least one key for each verify request

        For each verify_request, verify_request.deferred is called back with
        params (server_name, key_id, VerifyKey) if a key is found, or errbacked
        with a SynapseError if none of the keys are found.

        Args:
            verify_requests (list[VerifyKeyRequest]): list of verify requests
        """

        remaining_requests = set(
            (rq for rq in verify_requests if not rq.deferred.called)
        )

        @defer.inlineCallbacks
        def do_iterations():
            with Measure(self.clock, "get_server_verify_keys"):
                for f in self._key_fetchers:
                    if not remaining_requests:
                        return
                    yield self._attempt_key_fetches_with_fetcher(f, remaining_requests)

                # look for any requests which weren't satisfied
                with PreserveLoggingContext():
                    for verify_request in remaining_requests:
                        verify_request.deferred.errback(
                            SynapseError(
                                401,
                                "No key for %s with id %s"
                                % (verify_request.server_name, verify_request.key_ids),
                                Codes.UNAUTHORIZED,
                            )
                        )

        def on_err(err):
            # we don't really expect to get here, because any errors should already
            # have been caught and logged. But if we do, let's log the error and make
            # sure that all of the deferreds are resolved.
            logger.error("Unexpected error in _get_server_verify_keys: %s", err)
            with PreserveLoggingContext():
                for verify_request in remaining_requests:
                    if not verify_request.deferred.called:
                        verify_request.deferred.errback(err)

        run_in_background(do_iterations).addErrback(on_err)

    @defer.inlineCallbacks
    def _attempt_key_fetches_with_fetcher(self, fetcher, remaining_requests):
        """Use a key fetcher to attempt to satisfy some key requests

        Args:
            fetcher (KeyFetcher): fetcher to use to fetch the keys
            remaining_requests (set[VerifyKeyRequest]): outstanding key requests.
                Any successfully-completed requests will be reomved from the list.
        """
        # dict[str, set(str)]: keys to fetch for each server
        missing_keys = {}
        for verify_request in remaining_requests:
            # any completed requests should already have been removed
            assert not verify_request.deferred.called
            missing_keys.setdefault(verify_request.server_name, set()).update(
                verify_request.key_ids
            )

        results = yield fetcher.get_keys(missing_keys.items())

        completed = list()
        for verify_request in remaining_requests:
            server_name = verify_request.server_name

            # see if any of the keys we got this time are sufficient to
            # complete this VerifyKeyRequest.
            result_keys = results.get(server_name, {})
            for key_id in verify_request.key_ids:
                key = result_keys.get(key_id)
                if key:
                    with PreserveLoggingContext():
                        verify_request.deferred.callback(
                            (server_name, key_id, key.verify_key)
                        )
                    completed.append(verify_request)
                    break

        remaining_requests.difference_update(completed)


class KeyFetcher(object):
    def get_keys(self, server_name_and_key_ids):
        """
        Args:
            server_name_and_key_ids (iterable[Tuple[str, iterable[str]]]):
                list of (server_name, iterable[key_id]) tuples to fetch keys for
                Note that the iterables may be iterated more than once.

        Returns:
            Deferred[dict[str, dict[str, synapse.storage.keys.FetchKeyResult|None]]]:
                map from server_name -> key_id -> FetchKeyResult
        """
        raise NotImplementedError


class StoreKeyFetcher(KeyFetcher):
    """KeyFetcher impl which fetches keys from our data store"""

    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_keys(self, server_name_and_key_ids):
        """see KeyFetcher.get_keys"""
        keys_to_fetch = (
            (server_name, key_id)
            for server_name, key_ids in server_name_and_key_ids
            for key_id in key_ids
        )
        res = yield self.store.get_server_verify_keys(keys_to_fetch)
        keys = {}
        for (server_name, key_id), key in res.items():
            keys.setdefault(server_name, {})[key_id] = key
        defer.returnValue(keys)


class BaseV2KeyFetcher(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.config = hs.get_config()

    @defer.inlineCallbacks
    def process_v2_response(
        self, from_server, response_json, time_added_ms, requested_ids=[]
    ):
        """Parse a 'Server Keys' structure from the result of a /key request

        This is used to parse either the entirety of the response from
        GET /_matrix/key/v2/server, or a single entry from the list returned by
        POST /_matrix/key/v2/query.

        Checks that each signature in the response that claims to come from the origin
        server is valid, and that there is at least one such signature.

        Stores the json in server_keys_json so that it can be used for future responses
        to /_matrix/key/v2/query.

        Args:
            from_server (str): the name of the server producing this result: either
                the origin server for a /_matrix/key/v2/server request, or the notary
                for a /_matrix/key/v2/query.

            response_json (dict): the json-decoded Server Keys response object

            time_added_ms (int): the timestamp to record in server_keys_json

            requested_ids (iterable[str]): a list of the key IDs that were requested.
                We will store the json for these key ids as well as any that are
                actually in the response

        Returns:
            Deferred[dict[str, FetchKeyResult]]: map from key_id to result object
        """
        ts_valid_until_ms = response_json[u"valid_until_ts"]

        # start by extracting the keys from the response, since they may be required
        # to validate the signature on the response.
        verify_keys = {}
        for key_id, key_data in response_json["verify_keys"].items():
            if is_signing_algorithm_supported(key_id):
                key_base64 = key_data["key"]
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_keys[key_id] = FetchKeyResult(
                    verify_key=verify_key, valid_until_ts=ts_valid_until_ms
                )

        server_name = response_json["server_name"]
        verified = False
        for key_id in response_json["signatures"].get(server_name, {}):
            # each of the keys used for the signature must be present in the response
            # json.
            key = verify_keys.get(key_id)
            if not key:
                raise KeyLookupError(
                    "Key response is signed by key id %s:%s but that key is not "
                    "present in the response" % (server_name, key_id)
                )

            verify_signed_json(response_json, server_name, key.verify_key)
            verified = True

        if not verified:
            raise KeyLookupError(
                "Key response for %s is not signed by the origin server"
                % (server_name,)
            )

        for key_id, key_data in response_json["old_verify_keys"].items():
            if is_signing_algorithm_supported(key_id):
                key_base64 = key_data["key"]
                key_bytes = decode_base64(key_base64)
                verify_key = decode_verify_key_bytes(key_id, key_bytes)
                verify_keys[key_id] = FetchKeyResult(
                    verify_key=verify_key, valid_until_ts=key_data["expired_ts"]
                )

        # re-sign the json with our own key, so that it is ready if we are asked to
        # give it out as a notary server
        signed_key_json = sign_json(
            response_json, self.config.server_name, self.config.signing_key[0]
        )

        signed_key_json_bytes = encode_canonical_json(signed_key_json)

        # for reasons I don't quite understand, we store this json for the key ids we
        # requested, as well as those we got.
        updated_key_ids = set(requested_ids)
        updated_key_ids.update(verify_keys)

        yield logcontext.make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self.store.store_server_keys_json,
                        server_name=server_name,
                        key_id=key_id,
                        from_server=from_server,
                        ts_now_ms=time_added_ms,
                        ts_expires_ms=ts_valid_until_ms,
                        key_json_bytes=signed_key_json_bytes,
                    )
                    for key_id in updated_key_ids
                ],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        defer.returnValue(verify_keys)


class PerspectivesKeyFetcher(BaseV2KeyFetcher):
    """KeyFetcher impl which fetches keys from the "perspectives" servers"""

    def __init__(self, hs):
        super(PerspectivesKeyFetcher, self).__init__(hs)
        self.clock = hs.get_clock()
        self.client = hs.get_http_client()
        self.perspective_servers = self.config.perspectives

    @defer.inlineCallbacks
    def get_keys(self, server_name_and_key_ids):
        """see KeyFetcher.get_keys"""

        @defer.inlineCallbacks
        def get_key(perspective_name, perspective_keys):
            try:
                result = yield self.get_server_verify_key_v2_indirect(
                    server_name_and_key_ids, perspective_name, perspective_keys
                )
                defer.returnValue(result)
            except KeyLookupError as e:
                logger.warning("Key lookup failed from %r: %s", perspective_name, e)
            except Exception as e:
                logger.exception(
                    "Unable to get key from %r: %s %s",
                    perspective_name,
                    type(e).__name__,
                    str(e),
                )

            defer.returnValue({})

        results = yield logcontext.make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(get_key, p_name, p_keys)
                    for p_name, p_keys in self.perspective_servers.items()
                ],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        union_of_keys = {}
        for result in results:
            for server_name, keys in result.items():
                union_of_keys.setdefault(server_name, {}).update(keys)

        defer.returnValue(union_of_keys)

    @defer.inlineCallbacks
    def get_server_verify_key_v2_indirect(
        self, server_names_and_key_ids, perspective_name, perspective_keys
    ):
        """
        Args:
            server_names_and_key_ids (iterable[Tuple[str, iterable[str]]]):
                list of (server_name, iterable[key_id]) tuples to fetch keys for
            perspective_name (str): name of the notary server to query for the keys
            perspective_keys (dict[str, VerifyKey]): map of key_id->key for the
                notary server

        Returns:
            Deferred[dict[str, dict[str, synapse.storage.keys.FetchKeyResult]]]: map
                from server_name -> key_id -> FetchKeyResult

        Raises:
            KeyLookupError if there was an error processing the entire response from
                the server
        """
        logger.info(
            "Requesting keys %s from notary server %s",
            server_names_and_key_ids,
            perspective_name,
        )
        # TODO(mark): Set the minimum_valid_until_ts to that needed by
        # the events being validated or the current time if validating
        # an incoming request.
        try:
            query_response = yield self.client.post_json(
                destination=perspective_name,
                path="/_matrix/key/v2/query",
                data={
                    u"server_keys": {
                        server_name: {
                            key_id: {u"minimum_valid_until_ts": 0} for key_id in key_ids
                        }
                        for server_name, key_ids in server_names_and_key_ids
                    }
                },
                long_retries=True,
            )
        except (NotRetryingDestination, RequestSendFailed) as e:
            raise_from(KeyLookupError("Failed to connect to remote server"), e)
        except HttpResponseException as e:
            raise_from(KeyLookupError("Remote server returned an error"), e)

        keys = {}
        added_keys = []

        time_now_ms = self.clock.time_msec()

        for response in query_response["server_keys"]:
            # do this first, so that we can give useful errors thereafter
            server_name = response.get("server_name")
            if not isinstance(server_name, six.string_types):
                raise KeyLookupError(
                    "Malformed response from key notary server %s: invalid server_name"
                    % (perspective_name,)
                )

            try:
                processed_response = yield self._process_perspectives_response(
                    perspective_name,
                    perspective_keys,
                    response,
                    time_added_ms=time_now_ms,
                )
            except KeyLookupError as e:
                logger.warning(
                    "Error processing response from key notary server %s for origin "
                    "server %s: %s",
                    perspective_name,
                    server_name,
                    e,
                )
                # we continue to process the rest of the response
                continue

            added_keys.extend(
                (server_name, key_id, key) for key_id, key in processed_response.items()
            )
            keys.setdefault(server_name, {}).update(processed_response)

        yield self.store.store_server_verify_keys(
            perspective_name, time_now_ms, added_keys
        )

        defer.returnValue(keys)

    def _process_perspectives_response(
        self, perspective_name, perspective_keys, response, time_added_ms
    ):
        """Parse a 'Server Keys' structure from the result of a /key/query request

        Checks that the entry is correctly signed by the perspectives server, and then
        passes over to process_v2_response

        Args:
            perspective_name (str): the name of the notary server that produced this
                result

            perspective_keys (dict[str, VerifyKey]): map of key_id->key for the
                notary server

            response (dict): the json-decoded Server Keys response object

            time_added_ms (int): the timestamp to record in server_keys_json

        Returns:
            Deferred[dict[str, FetchKeyResult]]: map from key_id to result object
        """
        if (
            u"signatures" not in response
            or perspective_name not in response[u"signatures"]
        ):
            raise KeyLookupError("Response not signed by the notary server")

        verified = False
        for key_id in response[u"signatures"][perspective_name]:
            if key_id in perspective_keys:
                verify_signed_json(response, perspective_name, perspective_keys[key_id])
                verified = True

        if not verified:
            raise KeyLookupError(
                "Response not signed with a known key: signed with: %r, known keys: %r"
                % (
                    list(response[u"signatures"][perspective_name].keys()),
                    list(perspective_keys.keys()),
                )
            )

        return self.process_v2_response(
            perspective_name, response, time_added_ms=time_added_ms
        )


class ServerKeyFetcher(BaseV2KeyFetcher):
    """KeyFetcher impl which fetches keys from the origin servers"""

    def __init__(self, hs):
        super(ServerKeyFetcher, self).__init__(hs)
        self.clock = hs.get_clock()
        self.client = hs.get_http_client()

    @defer.inlineCallbacks
    def get_keys(self, server_name_and_key_ids):
        """see KeyFetcher.get_keys"""
        results = yield logcontext.make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self.get_server_verify_key_v2_direct, server_name, key_ids
                    )
                    for server_name, key_ids in server_name_and_key_ids
                ],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        merged = {}
        for result in results:
            merged.update(result)

        defer.returnValue(
            {server_name: keys for server_name, keys in merged.items() if keys}
        )

    @defer.inlineCallbacks
    def get_server_verify_key_v2_direct(self, server_name, key_ids):
        keys = {}  # type: dict[str, FetchKeyResult]

        for requested_key_id in key_ids:
            if requested_key_id in keys:
                continue

            time_now_ms = self.clock.time_msec()
            try:
                response = yield self.client.get_json(
                    destination=server_name,
                    path="/_matrix/key/v2/server/"
                    + urllib.parse.quote(requested_key_id),
                    ignore_backoff=True,
                )
            except (NotRetryingDestination, RequestSendFailed) as e:
                raise_from(KeyLookupError("Failed to connect to remote server"), e)
            except HttpResponseException as e:
                raise_from(KeyLookupError("Remote server returned an error"), e)

            if response["server_name"] != server_name:
                raise KeyLookupError(
                    "Expected a response for server %r not %r"
                    % (server_name, response["server_name"])
                )

            response_keys = yield self.process_v2_response(
                from_server=server_name,
                requested_ids=[requested_key_id],
                response_json=response,
                time_added_ms=time_now_ms,
            )
            yield self.store.store_server_verify_keys(
                server_name,
                time_now_ms,
                ((server_name, key_id, key) for key_id, key in response_keys.items()),
            )
            keys.update(response_keys)

        defer.returnValue({server_name: keys})


@defer.inlineCallbacks
def _handle_key_deferred(verify_request):
    """Waits for the key to become available, and then performs a verification

    Args:
        verify_request (VerifyKeyRequest):

    Returns:
        Deferred[None]

    Raises:
        SynapseError if there was a problem performing the verification
    """
    server_name = verify_request.server_name
    try:
        with PreserveLoggingContext():
            _, key_id, verify_key = yield verify_request.deferred
    except KeyLookupError as e:
        logger.warn(
            "Failed to download keys for %s: %s %s",
            server_name,
            type(e).__name__,
            str(e),
        )
        raise SynapseError(
            502, "Error downloading keys for %s" % (server_name,), Codes.UNAUTHORIZED
        )
    except Exception as e:
        logger.exception(
            "Got Exception when downloading keys for %s: %s %s",
            server_name,
            type(e).__name__,
            str(e),
        )
        raise SynapseError(
            401,
            "No key for %s with id %s" % (server_name, verify_request.key_ids),
            Codes.UNAUTHORIZED,
        )

    json_object = verify_request.json_object

    logger.debug(
        "Got key %s %s:%s for server %s, verifying"
        % (key_id, verify_key.alg, verify_key.version, server_name)
    )
    try:
        verify_signed_json(json_object, server_name, verify_key)
    except SignatureVerifyException as e:
        logger.debug(
            "Error verifying signature for %s:%s:%s with key %s: %s",
            server_name,
            verify_key.alg,
            verify_key.version,
            encode_verify_key_base64(verify_key),
            str(e),
        )
        raise SynapseError(
            401,
            "Invalid signature for server %s with key %s:%s: %s"
            % (server_name, verify_key.alg, verify_key.version, str(e)),
            Codes.UNAUTHORIZED,
        )
