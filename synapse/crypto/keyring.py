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

import abc
import logging
import urllib
from collections import defaultdict
from typing import TYPE_CHECKING, Callable, Dict, Iterable, List, Optional, Set, Tuple

import attr
from signedjson.key import (
    decode_verify_key_bytes,
    encode_verify_key_base64,
    is_signing_algorithm_supported,
)
from signedjson.sign import (
    SignatureVerifyException,
    encode_canonical_json,
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
from synapse.config.key import TrustedKeyServer
from synapse.events import EventBase
from synapse.events.utils import prune_event_dict
from synapse.logging.context import (
    PreserveLoggingContext,
    make_deferred_yieldable,
    preserve_fn,
    run_in_background,
)
from synapse.storage.keys import FetchKeyResult
from synapse.types import JsonDict
from synapse.util import unwrapFirstError
from synapse.util.async_helpers import yieldable_gather_results
from synapse.util.metrics import Measure
from synapse.util.retryutils import NotRetryingDestination

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, cmp=False)
class VerifyJsonRequest:
    """
    A request to verify a JSON object.

    Attributes:
        server_name: The name of the server to verify against.

        get_json_object: A callback to fetch the JSON object to verify.
            A callback is used to allow deferring the creation of the JSON
            object to verify until needed, e.g. for events we can defer
            creating the redacted copy. This reduces the memory usage when
            there are large numbers of in flight requests.

        minimum_valid_until_ts: time at which we require the signing key to
            be valid. (0 implies we don't care)

        request_name: The name of the request.

        key_ids: The set of key_ids to that could be used to verify the JSON object

        key_ready (Deferred[str, str, nacl.signing.VerifyKey]):
            A deferred (server_name, key_id, verify_key) tuple that resolves when
            a verify key has been fetched. The deferreds' callbacks are run with no
            logcontext.

            If we are unable to find a key which satisfies the request, the deferred
            errbacks with an M_UNAUTHORIZED SynapseError.
    """

    server_name = attr.ib(type=str)
    get_json_object = attr.ib(type=Callable[[], JsonDict])
    minimum_valid_until_ts = attr.ib(type=int)
    request_name = attr.ib(type=str)
    key_ids = attr.ib(type=List[str])
    key_ready = attr.ib(default=attr.Factory(defer.Deferred), type=defer.Deferred)

    @staticmethod
    def from_json_object(
        server_name: str,
        json_object: JsonDict,
        minimum_valid_until_ms: int,
        request_name: str,
    ):
        """Create a VerifyJsonRequest to verify all signatures on a signed JSON
        object for the given server.
        """
        key_ids = signature_ids(json_object, server_name)
        return VerifyJsonRequest(
            server_name,
            lambda: json_object,
            minimum_valid_until_ms,
            request_name=request_name,
            key_ids=key_ids,
        )

    @staticmethod
    def from_event(
        server_name: str,
        event: EventBase,
        minimum_valid_until_ms: int,
    ):
        """Create a VerifyJsonRequest to verify all signatures on an event
        object for the given server.
        """
        key_ids = list(event.signatures.get(server_name, []))
        return VerifyJsonRequest(
            server_name,
            # We defer creating the redacted json object, as it uses a lot more
            # memory than the Event object itself.
            lambda: prune_event_dict(event.room_version, event.get_pdu_json()),
            minimum_valid_until_ms,
            request_name=event.event_id,
            key_ids=key_ids,
        )


class KeyLookupError(ValueError):
    pass


class Keyring:
    def __init__(
        self, hs: "HomeServer", key_fetchers: "Optional[Iterable[KeyFetcher]]" = None
    ):
        self.clock = hs.get_clock()

        if key_fetchers is None:
            key_fetchers = (
                StoreKeyFetcher(hs),
                PerspectivesKeyFetcher(hs),
                ServerKeyFetcher(hs),
            )
        self._key_fetchers = key_fetchers

        # map from server name to Deferred. Has an entry for each server with
        # an ongoing key download; the Deferred completes once the download
        # completes.
        #
        # These are regular, logcontext-agnostic Deferreds.
        self.key_downloads = {}  # type: Dict[str, defer.Deferred]

    def verify_json_for_server(
        self,
        server_name: str,
        json_object: JsonDict,
        validity_time: int,
        request_name: str,
    ) -> defer.Deferred:
        """Verify that a JSON object has been signed by a given server

        Args:
            server_name: name of the server which must have signed this object

            json_object: object to be checked

            validity_time: timestamp at which we require the signing key to
                be valid. (0 implies we don't care)

            request_name: an identifier for this json object (eg, an event id)
                for logging.

        Returns:
            Deferred[None]: completes if the the object was correctly signed, otherwise
                errbacks with an error
        """
        request = VerifyJsonRequest.from_json_object(
            server_name,
            json_object,
            validity_time,
            request_name,
        )
        requests = (request,)
        return make_deferred_yieldable(self._verify_objects(requests)[0])

    def verify_json_objects_for_server(
        self, server_and_json: Iterable[Tuple[str, dict, int, str]]
    ) -> List[defer.Deferred]:
        """Bulk verifies signatures of json objects, bulk fetching keys as
        necessary.

        Args:
            server_and_json:
                Iterable of (server_name, json_object, validity_time, request_name)
                tuples.

                validity_time is a timestamp at which the signing key must be
                valid.

                request_name is an identifier for this json object (eg, an event id)
                for logging.

        Returns:
            List<Deferred[None]>: for each input triplet, a deferred indicating success
                or failure to verify each json object's signature for the given
                server_name. The deferreds run their callbacks in the sentinel
                logcontext.
        """
        return self._verify_objects(
            VerifyJsonRequest.from_json_object(
                server_name, json_object, validity_time, request_name
            )
            for server_name, json_object, validity_time, request_name in server_and_json
        )

    def verify_events_for_server(
        self, server_and_events: Iterable[Tuple[str, EventBase, int]]
    ) -> List[defer.Deferred]:
        """Bulk verification of signatures on events.

        Args:
            server_and_events:
                Iterable of `(server_name, event, validity_time)` tuples.

                `server_name` is which server we are verifying the signature for
                on the event.

                `event` is the event that we'll verify the signatures of for
                the given `server_name`.

                `validity_time` is a timestamp at which the signing key must be
                valid.

        Returns:
            List<Deferred[None]>: for each input triplet, a deferred indicating success
                or failure to verify each event's signature for the given
                server_name. The deferreds run their callbacks in the sentinel
                logcontext.
        """
        return self._verify_objects(
            VerifyJsonRequest.from_event(server_name, event, validity_time)
            for server_name, event, validity_time in server_and_events
        )

    def _verify_objects(
        self, verify_requests: Iterable[VerifyJsonRequest]
    ) -> List[defer.Deferred]:
        """Does the work of verify_json_[objects_]for_server


        Args:
            verify_requests: Iterable of verification requests.

        Returns:
            List<Deferred[None]>: for each input item, a deferred indicating success
                or failure to verify each json object's signature for the given
                server_name. The deferreds run their callbacks in the sentinel
                logcontext.
        """
        # a list of VerifyJsonRequests which are awaiting a key lookup
        key_lookups = []
        handle = preserve_fn(_handle_key_deferred)

        def process(verify_request: VerifyJsonRequest) -> defer.Deferred:
            """Process an entry in the request list

            Adds a key request to key_lookups, and returns a deferred which
            will complete or fail (in the sentinel context) when verification completes.
            """
            if not verify_request.key_ids:
                return defer.fail(
                    SynapseError(
                        400,
                        "Not signed by %s" % (verify_request.server_name,),
                        Codes.UNAUTHORIZED,
                    )
                )

            logger.debug(
                "Verifying %s for %s with key_ids %s, min_validity %i",
                verify_request.request_name,
                verify_request.server_name,
                verify_request.key_ids,
                verify_request.minimum_valid_until_ts,
            )

            # add the key request to the queue, but don't start it off yet.
            key_lookups.append(verify_request)

            # now run _handle_key_deferred, which will wait for the key request
            # to complete and then do the verification.
            #
            # We want _handle_key_request to log to the right context, so we
            # wrap it with preserve_fn (aka run_in_background)
            return handle(verify_request)

        results = [process(r) for r in verify_requests]

        if key_lookups:
            run_in_background(self._start_key_lookups, key_lookups)

        return results

    async def _start_key_lookups(
        self, verify_requests: List[VerifyJsonRequest]
    ) -> None:
        """Sets off the key fetches for each verify request

        Once each fetch completes, verify_request.key_ready will be resolved.

        Args:
            verify_requests:
        """

        try:
            # map from server name to a set of outstanding request ids
            server_to_request_ids = {}  # type: Dict[str, Set[int]]

            for verify_request in verify_requests:
                server_name = verify_request.server_name
                request_id = id(verify_request)
                server_to_request_ids.setdefault(server_name, set()).add(request_id)

            # Wait for any previous lookups to complete before proceeding.
            await self.wait_for_previous_lookups(server_to_request_ids.keys())

            # take out a lock on each of the servers by sticking a Deferred in
            # key_downloads
            for server_name in server_to_request_ids.keys():
                self.key_downloads[server_name] = defer.Deferred()
                logger.debug("Got key lookup lock on %s", server_name)

            # When we've finished fetching all the keys for a given server_name,
            # drop the lock by resolving the deferred in key_downloads.
            def drop_server_lock(server_name):
                d = self.key_downloads.pop(server_name)
                d.callback(None)

            def lookup_done(res, verify_request):
                server_name = verify_request.server_name
                server_requests = server_to_request_ids[server_name]
                server_requests.remove(id(verify_request))

                # if there are no more requests for this server, we can drop the lock.
                if not server_requests:
                    logger.debug("Releasing key lookup lock on %s", server_name)
                    drop_server_lock(server_name)

                return res

            for verify_request in verify_requests:
                verify_request.key_ready.addBoth(lookup_done, verify_request)

            # Actually start fetching keys.
            self._get_server_verify_keys(verify_requests)
        except Exception:
            logger.exception("Error starting key lookups")

    async def wait_for_previous_lookups(self, server_names: Iterable[str]) -> None:
        """Waits for any previous key lookups for the given servers to finish.

        Args:
            server_names: list of servers which we want to look up

        Returns:
            Resolves once all key lookups for the given servers have
                completed. Follows the synapse rules of logcontext preservation.
        """
        loop_count = 1
        while True:
            wait_on = [
                (server_name, self.key_downloads[server_name])
                for server_name in server_names
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
                await defer.DeferredList((w[1] for w in wait_on))

            loop_count += 1

    def _get_server_verify_keys(self, verify_requests: List[VerifyJsonRequest]) -> None:
        """Tries to find at least one key for each verify request

        For each verify_request, verify_request.key_ready is called back with
        params (server_name, key_id, VerifyKey) if a key is found, or errbacked
        with a SynapseError if none of the keys are found.

        Args:
            verify_requests: list of verify requests
        """

        remaining_requests = {rq for rq in verify_requests if not rq.key_ready.called}

        async def do_iterations():
            try:
                with Measure(self.clock, "get_server_verify_keys"):
                    for f in self._key_fetchers:
                        if not remaining_requests:
                            return
                        await self._attempt_key_fetches_with_fetcher(
                            f, remaining_requests
                        )

                    # look for any requests which weren't satisfied
                    while remaining_requests:
                        verify_request = remaining_requests.pop()
                        rq_str = (
                            "VerifyJsonRequest(server=%s, key_ids=%s, min_valid=%i)"
                            % (
                                verify_request.server_name,
                                verify_request.key_ids,
                                verify_request.minimum_valid_until_ts,
                            )
                        )

                        # If we run the errback immediately, it may cancel our
                        # loggingcontext while we are still in it, so instead we
                        # schedule it for the next time round the reactor.
                        #
                        # (this also ensures that we don't get a stack overflow if we
                        # has a massive queue of lookups waiting for this server).
                        self.clock.call_later(
                            0,
                            verify_request.key_ready.errback,
                            SynapseError(
                                401,
                                "Failed to find any key to satisfy %s" % (rq_str,),
                                Codes.UNAUTHORIZED,
                            ),
                        )
            except Exception as err:
                # we don't really expect to get here, because any errors should already
                # have been caught and logged. But if we do, let's log the error and make
                # sure that all of the deferreds are resolved.
                logger.error("Unexpected error in _get_server_verify_keys: %s", err)
                with PreserveLoggingContext():
                    for verify_request in remaining_requests:
                        if not verify_request.key_ready.called:
                            verify_request.key_ready.errback(err)

        run_in_background(do_iterations)

    async def _attempt_key_fetches_with_fetcher(
        self, fetcher: "KeyFetcher", remaining_requests: Set[VerifyJsonRequest]
    ):
        """Use a key fetcher to attempt to satisfy some key requests

        Args:
            fetcher: fetcher to use to fetch the keys
            remaining_requests: outstanding key requests.
                Any successfully-completed requests will be removed from the list.
        """
        # The keys to fetch.
        # server_name -> key_id -> min_valid_ts
        missing_keys = defaultdict(dict)  # type: Dict[str, Dict[str, int]]

        for verify_request in remaining_requests:
            # any completed requests should already have been removed
            assert not verify_request.key_ready.called
            keys_for_server = missing_keys[verify_request.server_name]

            for key_id in verify_request.key_ids:
                # If we have several requests for the same key, then we only need to
                # request that key once, but we should do so with the greatest
                # min_valid_until_ts of the requests, so that we can satisfy all of
                # the requests.
                keys_for_server[key_id] = max(
                    keys_for_server.get(key_id, -1),
                    verify_request.minimum_valid_until_ts,
                )

        results = await fetcher.get_keys(missing_keys)

        completed = []
        for verify_request in remaining_requests:
            server_name = verify_request.server_name

            # see if any of the keys we got this time are sufficient to
            # complete this VerifyJsonRequest.
            result_keys = results.get(server_name, {})
            for key_id in verify_request.key_ids:
                fetch_key_result = result_keys.get(key_id)
                if not fetch_key_result:
                    # we didn't get a result for this key
                    continue

                if (
                    fetch_key_result.valid_until_ts
                    < verify_request.minimum_valid_until_ts
                ):
                    # key was not valid at this point
                    continue

                # we have a valid key for this request. If we run the callback
                # immediately, it may cancel our loggingcontext while we are still in
                # it, so instead we schedule it for the next time round the reactor.
                #
                # (this also ensures that we don't get a stack overflow if we had
                # a massive queue of lookups waiting for this server).
                logger.debug(
                    "Found key %s:%s for %s",
                    server_name,
                    key_id,
                    verify_request.request_name,
                )
                self.clock.call_later(
                    0,
                    verify_request.key_ready.callback,
                    (server_name, key_id, fetch_key_result.verify_key),
                )
                completed.append(verify_request)
                break

        remaining_requests.difference_update(completed)


class KeyFetcher(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def get_keys(
        self, keys_to_fetch: Dict[str, Dict[str, int]]
    ) -> Dict[str, Dict[str, FetchKeyResult]]:
        """
        Args:
            keys_to_fetch:
                the keys to be fetched. server_name -> key_id -> min_valid_ts

        Returns:
            Map from server_name -> key_id -> FetchKeyResult
        """
        raise NotImplementedError


class StoreKeyFetcher(KeyFetcher):
    """KeyFetcher impl which fetches keys from our data store"""

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()

    async def get_keys(
        self, keys_to_fetch: Dict[str, Dict[str, int]]
    ) -> Dict[str, Dict[str, FetchKeyResult]]:
        """see KeyFetcher.get_keys"""

        key_ids_to_fetch = (
            (server_name, key_id)
            for server_name, keys_for_server in keys_to_fetch.items()
            for key_id in keys_for_server.keys()
        )

        res = await self.store.get_server_verify_keys(key_ids_to_fetch)
        keys = {}  # type: Dict[str, Dict[str, FetchKeyResult]]
        for (server_name, key_id), key in res.items():
            keys.setdefault(server_name, {})[key_id] = key
        return keys


class BaseV2KeyFetcher(KeyFetcher):
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        self.config = hs.config

    async def process_v2_response(
        self, from_server: str, response_json: JsonDict, time_added_ms: int
    ) -> Dict[str, FetchKeyResult]:
        """Parse a 'Server Keys' structure from the result of a /key request

        This is used to parse either the entirety of the response from
        GET /_matrix/key/v2/server, or a single entry from the list returned by
        POST /_matrix/key/v2/query.

        Checks that each signature in the response that claims to come from the origin
        server is valid, and that there is at least one such signature.

        Stores the json in server_keys_json so that it can be used for future responses
        to /_matrix/key/v2/query.

        Args:
            from_server: the name of the server producing this result: either
                the origin server for a /_matrix/key/v2/server request, or the notary
                for a /_matrix/key/v2/query.

            response_json: the json-decoded Server Keys response object

            time_added_ms: the timestamp to record in server_keys_json

        Returns:
            Map from key_id to result object
        """
        ts_valid_until_ms = response_json["valid_until_ts"]

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
            key = verify_keys.get(key_id)
            if not key:
                # the key may not be present in verify_keys if:
                #  * we got the key from the notary server, and:
                #  * the key belongs to the notary server, and:
                #  * the notary server is using a different key to sign notary
                #    responses.
                continue

            verify_signed_json(response_json, server_name, key.verify_key)
            verified = True
            break

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

        key_json_bytes = encode_canonical_json(response_json)

        await make_deferred_yieldable(
            defer.gatherResults(
                [
                    run_in_background(
                        self.store.store_server_keys_json,
                        server_name=server_name,
                        key_id=key_id,
                        from_server=from_server,
                        ts_now_ms=time_added_ms,
                        ts_expires_ms=ts_valid_until_ms,
                        key_json_bytes=key_json_bytes,
                    )
                    for key_id in verify_keys
                ],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        return verify_keys


class PerspectivesKeyFetcher(BaseV2KeyFetcher):
    """KeyFetcher impl which fetches keys from the "perspectives" servers"""

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.clock = hs.get_clock()
        self.client = hs.get_federation_http_client()
        self.key_servers = self.config.key_servers

    async def get_keys(
        self, keys_to_fetch: Dict[str, Dict[str, int]]
    ) -> Dict[str, Dict[str, FetchKeyResult]]:
        """see KeyFetcher.get_keys"""

        async def get_key(key_server: TrustedKeyServer) -> Dict:
            try:
                return await self.get_server_verify_key_v2_indirect(
                    keys_to_fetch, key_server
                )
            except KeyLookupError as e:
                logger.warning(
                    "Key lookup failed from %r: %s", key_server.server_name, e
                )
            except Exception as e:
                logger.exception(
                    "Unable to get key from %r: %s %s",
                    key_server.server_name,
                    type(e).__name__,
                    str(e),
                )

            return {}

        results = await make_deferred_yieldable(
            defer.gatherResults(
                [run_in_background(get_key, server) for server in self.key_servers],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        union_of_keys = {}  # type: Dict[str, Dict[str, FetchKeyResult]]
        for result in results:
            for server_name, keys in result.items():
                union_of_keys.setdefault(server_name, {}).update(keys)

        return union_of_keys

    async def get_server_verify_key_v2_indirect(
        self, keys_to_fetch: Dict[str, Dict[str, int]], key_server: TrustedKeyServer
    ) -> Dict[str, Dict[str, FetchKeyResult]]:
        """
        Args:
            keys_to_fetch:
                the keys to be fetched. server_name -> key_id -> min_valid_ts

            key_server: notary server to query for the keys

        Returns:
            Map from server_name -> key_id -> FetchKeyResult

        Raises:
            KeyLookupError if there was an error processing the entire response from
                the server
        """
        perspective_name = key_server.server_name
        logger.info(
            "Requesting keys %s from notary server %s",
            keys_to_fetch.items(),
            perspective_name,
        )

        try:
            query_response = await self.client.post_json(
                destination=perspective_name,
                path="/_matrix/key/v2/query",
                data={
                    "server_keys": {
                        server_name: {
                            key_id: {"minimum_valid_until_ts": min_valid_ts}
                            for key_id, min_valid_ts in server_keys.items()
                        }
                        for server_name, server_keys in keys_to_fetch.items()
                    }
                },
            )
        except (NotRetryingDestination, RequestSendFailed) as e:
            # these both have str() representations which we can't really improve upon
            raise KeyLookupError(str(e))
        except HttpResponseException as e:
            raise KeyLookupError("Remote server returned an error: %s" % (e,))

        keys = {}  # type: Dict[str, Dict[str, FetchKeyResult]]
        added_keys = []  # type: List[Tuple[str, str, FetchKeyResult]]

        time_now_ms = self.clock.time_msec()

        assert isinstance(query_response, dict)
        for response in query_response["server_keys"]:
            # do this first, so that we can give useful errors thereafter
            server_name = response.get("server_name")
            if not isinstance(server_name, str):
                raise KeyLookupError(
                    "Malformed response from key notary server %s: invalid server_name"
                    % (perspective_name,)
                )

            try:
                self._validate_perspectives_response(key_server, response)

                processed_response = await self.process_v2_response(
                    perspective_name, response, time_added_ms=time_now_ms
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

        await self.store.store_server_verify_keys(
            perspective_name, time_now_ms, added_keys
        )

        return keys

    def _validate_perspectives_response(
        self, key_server: TrustedKeyServer, response: JsonDict
    ) -> None:
        """Optionally check the signature on the result of a /key/query request

        Args:
            key_server: the notary server that produced this result

            response: the json-decoded Server Keys response object
        """
        perspective_name = key_server.server_name
        perspective_keys = key_server.verify_keys

        if perspective_keys is None:
            # signature checking is disabled on this server
            return

        if (
            "signatures" not in response
            or perspective_name not in response["signatures"]
        ):
            raise KeyLookupError("Response not signed by the notary server")

        verified = False
        for key_id in response["signatures"][perspective_name]:
            if key_id in perspective_keys:
                verify_signed_json(response, perspective_name, perspective_keys[key_id])
                verified = True

        if not verified:
            raise KeyLookupError(
                "Response not signed with a known key: signed with: %r, known keys: %r"
                % (
                    list(response["signatures"][perspective_name].keys()),
                    list(perspective_keys.keys()),
                )
            )


class ServerKeyFetcher(BaseV2KeyFetcher):
    """KeyFetcher impl which fetches keys from the origin servers"""

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.clock = hs.get_clock()
        self.client = hs.get_federation_http_client()

    async def get_keys(
        self, keys_to_fetch: Dict[str, Dict[str, int]]
    ) -> Dict[str, Dict[str, FetchKeyResult]]:
        """
        Args:
            keys_to_fetch:
                the keys to be fetched. server_name -> key_ids

        Returns:
            Map from server_name -> key_id -> FetchKeyResult
        """

        results = {}

        async def get_key(key_to_fetch_item: Tuple[str, Dict[str, int]]) -> None:
            server_name, key_ids = key_to_fetch_item
            try:
                keys = await self.get_server_verify_key_v2_direct(server_name, key_ids)
                results[server_name] = keys
            except KeyLookupError as e:
                logger.warning(
                    "Error looking up keys %s from %s: %s", key_ids, server_name, e
                )
            except Exception:
                logger.exception("Error getting keys %s from %s", key_ids, server_name)

        await yieldable_gather_results(get_key, keys_to_fetch.items())
        return results

    async def get_server_verify_key_v2_direct(
        self, server_name: str, key_ids: Iterable[str]
    ) -> Dict[str, FetchKeyResult]:
        """

        Args:
            server_name:
            key_ids:

        Returns:
            Map from key ID to lookup result

        Raises:
            KeyLookupError if there was a problem making the lookup
        """
        keys = {}  # type: Dict[str, FetchKeyResult]

        for requested_key_id in key_ids:
            # we may have found this key as a side-effect of asking for another.
            if requested_key_id in keys:
                continue

            time_now_ms = self.clock.time_msec()
            try:
                response = await self.client.get_json(
                    destination=server_name,
                    path="/_matrix/key/v2/server/"
                    + urllib.parse.quote(requested_key_id),
                    ignore_backoff=True,
                    # we only give the remote server 10s to respond. It should be an
                    # easy request to handle, so if it doesn't reply within 10s, it's
                    # probably not going to.
                    #
                    # Furthermore, when we are acting as a notary server, we cannot
                    # wait all day for all of the origin servers, as the requesting
                    # server will otherwise time out before we can respond.
                    #
                    # (Note that get_json may make 4 attempts, so this can still take
                    # almost 45 seconds to fetch the headers, plus up to another 60s to
                    # read the response).
                    timeout=10000,
                )
            except (NotRetryingDestination, RequestSendFailed) as e:
                # these both have str() representations which we can't really improve
                # upon
                raise KeyLookupError(str(e))
            except HttpResponseException as e:
                raise KeyLookupError("Remote server returned an error: %s" % (e,))

            assert isinstance(response, dict)
            if response["server_name"] != server_name:
                raise KeyLookupError(
                    "Expected a response for server %r not %r"
                    % (server_name, response["server_name"])
                )

            response_keys = await self.process_v2_response(
                from_server=server_name,
                response_json=response,
                time_added_ms=time_now_ms,
            )
            await self.store.store_server_verify_keys(
                server_name,
                time_now_ms,
                ((server_name, key_id, key) for key_id, key in response_keys.items()),
            )
            keys.update(response_keys)

        return keys


async def _handle_key_deferred(verify_request: VerifyJsonRequest) -> None:
    """Waits for the key to become available, and then performs a verification

    Args:
        verify_request:

    Raises:
        SynapseError if there was a problem performing the verification
    """
    server_name = verify_request.server_name
    with PreserveLoggingContext():
        _, key_id, verify_key = await verify_request.key_ready

    json_object = verify_request.get_json_object()

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
