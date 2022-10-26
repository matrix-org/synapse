# Copyright 2014-2016 OpenMarket Ltd
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

"""Contains exceptions and error codes."""

import logging
import typing
from enum import Enum
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Union

from twisted.web import http

from synapse.util import json_decoder

if typing.TYPE_CHECKING:
    from synapse.config.homeserver import HomeServerConfig
    from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class Codes(str, Enum):
    """
    All known error codes, as an enum of strings.
    """

    UNRECOGNIZED = "M_UNRECOGNIZED"
    UNAUTHORIZED = "M_UNAUTHORIZED"
    FORBIDDEN = "M_FORBIDDEN"
    BAD_JSON = "M_BAD_JSON"
    NOT_JSON = "M_NOT_JSON"
    USER_IN_USE = "M_USER_IN_USE"
    ROOM_IN_USE = "M_ROOM_IN_USE"
    BAD_PAGINATION = "M_BAD_PAGINATION"
    BAD_STATE = "M_BAD_STATE"
    UNKNOWN = "M_UNKNOWN"
    NOT_FOUND = "M_NOT_FOUND"
    MISSING_TOKEN = "M_MISSING_TOKEN"
    UNKNOWN_TOKEN = "M_UNKNOWN_TOKEN"
    GUEST_ACCESS_FORBIDDEN = "M_GUEST_ACCESS_FORBIDDEN"
    LIMIT_EXCEEDED = "M_LIMIT_EXCEEDED"
    CAPTCHA_NEEDED = "M_CAPTCHA_NEEDED"
    CAPTCHA_INVALID = "M_CAPTCHA_INVALID"
    MISSING_PARAM = "M_MISSING_PARAM"
    INVALID_PARAM = "M_INVALID_PARAM"
    TOO_LARGE = "M_TOO_LARGE"
    EXCLUSIVE = "M_EXCLUSIVE"
    THREEPID_AUTH_FAILED = "M_THREEPID_AUTH_FAILED"
    THREEPID_IN_USE = "M_THREEPID_IN_USE"
    THREEPID_NOT_FOUND = "M_THREEPID_NOT_FOUND"
    THREEPID_DENIED = "M_THREEPID_DENIED"
    INVALID_USERNAME = "M_INVALID_USERNAME"
    SERVER_NOT_TRUSTED = "M_SERVER_NOT_TRUSTED"
    CONSENT_NOT_GIVEN = "M_CONSENT_NOT_GIVEN"
    CANNOT_LEAVE_SERVER_NOTICE_ROOM = "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM"
    RESOURCE_LIMIT_EXCEEDED = "M_RESOURCE_LIMIT_EXCEEDED"
    UNSUPPORTED_ROOM_VERSION = "M_UNSUPPORTED_ROOM_VERSION"
    INCOMPATIBLE_ROOM_VERSION = "M_INCOMPATIBLE_ROOM_VERSION"
    WRONG_ROOM_KEYS_VERSION = "M_WRONG_ROOM_KEYS_VERSION"
    EXPIRED_ACCOUNT = "ORG_MATRIX_EXPIRED_ACCOUNT"
    PASSWORD_TOO_SHORT = "M_PASSWORD_TOO_SHORT"
    PASSWORD_NO_DIGIT = "M_PASSWORD_NO_DIGIT"
    PASSWORD_NO_UPPERCASE = "M_PASSWORD_NO_UPPERCASE"
    PASSWORD_NO_LOWERCASE = "M_PASSWORD_NO_LOWERCASE"
    PASSWORD_NO_SYMBOL = "M_PASSWORD_NO_SYMBOL"
    PASSWORD_IN_DICTIONARY = "M_PASSWORD_IN_DICTIONARY"
    WEAK_PASSWORD = "M_WEAK_PASSWORD"
    INVALID_SIGNATURE = "M_INVALID_SIGNATURE"
    USER_DEACTIVATED = "M_USER_DEACTIVATED"

    # Part of MSC3848
    # https://github.com/matrix-org/matrix-spec-proposals/pull/3848
    ALREADY_JOINED = "ORG.MATRIX.MSC3848.ALREADY_JOINED"
    NOT_JOINED = "ORG.MATRIX.MSC3848.NOT_JOINED"
    INSUFFICIENT_POWER = "ORG.MATRIX.MSC3848.INSUFFICIENT_POWER"

    # The account has been suspended on the server.
    # By opposition to `USER_DEACTIVATED`, this is a reversible measure
    # that can possibly be appealed and reverted.
    # Part of MSC3823.
    USER_ACCOUNT_SUSPENDED = "ORG.MATRIX.MSC3823.USER_ACCOUNT_SUSPENDED"

    BAD_ALIAS = "M_BAD_ALIAS"
    # For restricted join rules.
    UNABLE_AUTHORISE_JOIN = "M_UNABLE_TO_AUTHORISE_JOIN"
    UNABLE_TO_GRANT_JOIN = "M_UNABLE_TO_GRANT_JOIN"

    UNREDACTED_CONTENT_DELETED = "FI.MAU.MSC2815_UNREDACTED_CONTENT_DELETED"

    # Returned for federation requests where we can't process a request as we
    # can't ensure the sending server is in a room which is partial-stated on
    # our side.
    # Part of MSC3895.
    UNABLE_DUE_TO_PARTIAL_STATE = "ORG.MATRIX.MSC3895_UNABLE_DUE_TO_PARTIAL_STATE"

    USER_AWAITING_APPROVAL = "ORG.MATRIX.MSC3866_USER_AWAITING_APPROVAL"


class CodeMessageException(RuntimeError):
    """An exception with integer code and message string attributes.

    Attributes:
        code: HTTP error code
        msg: string describing the error
    """

    def __init__(self, code: Union[int, HTTPStatus], msg: str):
        super().__init__("%d: %s" % (code, msg))

        # Some calls to this method pass instances of http.HTTPStatus for `code`.
        # While HTTPStatus is a subclass of int, it has magic __str__ methods
        # which emit `HTTPStatus.FORBIDDEN` when converted to a str, instead of `403`.
        # This causes inconsistency in our log lines.
        #
        # To eliminate this behaviour, we convert them to their integer equivalents here.
        self.code = int(code)
        self.msg = msg


class RedirectException(CodeMessageException):
    """A pseudo-error indicating that we want to redirect the client to a different
    location

    Attributes:
        cookies: a list of set-cookies values to add to the response. For example:
           b"sessionId=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
    """

    def __init__(self, location: bytes, http_code: int = http.FOUND):
        """

        Args:
            location: the URI to redirect to
            http_code: the HTTP response code
        """
        msg = "Redirect to %s" % (location.decode("utf-8"),)
        super().__init__(code=http_code, msg=msg)
        self.location = location

        self.cookies: List[bytes] = []


class SynapseError(CodeMessageException):
    """A base exception type for matrix errors which have an errcode and error
    message (as well as an HTTP status code). These often bubble all the way up to the
    client API response so the error code and status often reach the client directly as
    defined here. If the error doesn't make sense to present to a client, then it
    probably shouldn't be a `SynapseError`. For example, if we contact another
    homeserver over federation, we shouldn't automatically ferry response errors back to
    the client on our end (a 500 from a remote server does not make sense to a client
    when our server did not experience a 500).

    Attributes:
        errcode: Matrix error code e.g 'M_FORBIDDEN'
    """

    def __init__(
        self,
        code: int,
        msg: str,
        errcode: str = Codes.UNKNOWN,
        additional_fields: Optional[Dict] = None,
    ):
        """Constructs a synapse error.

        Args:
            code: The integer error code (an HTTP response code)
            msg: The human-readable error message.
            errcode: The matrix error code e.g 'M_FORBIDDEN'
        """
        super().__init__(code, msg)
        self.errcode = errcode
        if additional_fields is None:
            self._additional_fields: Dict = {}
        else:
            self._additional_fields = dict(additional_fields)

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(self.msg, self.errcode, **self._additional_fields)


class InvalidAPICallError(SynapseError):
    """You called an existing API endpoint, but fed that endpoint
    invalid or incomplete data."""

    def __init__(self, msg: str):
        super().__init__(HTTPStatus.BAD_REQUEST, msg, Codes.BAD_JSON)


class ProxiedRequestError(SynapseError):
    """An error from a general matrix endpoint, eg. from a proxied Matrix API call.

    Attributes:
        errcode: Matrix error code e.g 'M_FORBIDDEN'
    """

    def __init__(
        self,
        code: int,
        msg: str,
        errcode: str = Codes.UNKNOWN,
        additional_fields: Optional[Dict] = None,
    ):
        super().__init__(code, msg, errcode, additional_fields)


class ConsentNotGivenError(SynapseError):
    """The error returned to the client when the user has not consented to the
    privacy policy.
    """

    def __init__(self, msg: str, consent_uri: str):
        """Constructs a ConsentNotGivenError

        Args:
            msg: The human-readable error message
            consent_url: The URL where the user can give their consent
        """
        super().__init__(
            code=HTTPStatus.FORBIDDEN, msg=msg, errcode=Codes.CONSENT_NOT_GIVEN
        )
        self._consent_uri = consent_uri

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(self.msg, self.errcode, consent_uri=self._consent_uri)


class UserDeactivatedError(SynapseError):
    """The error returned to the client when the user attempted to access an
    authenticated endpoint, but the account has been deactivated.
    """

    def __init__(self, msg: str):
        """Constructs a UserDeactivatedError

        Args:
            msg: The human-readable error message
        """
        super().__init__(
            code=HTTPStatus.FORBIDDEN, msg=msg, errcode=Codes.USER_DEACTIVATED
        )


class FederationDeniedError(SynapseError):
    """An error raised when the server tries to federate with a server which
    is not on its federation whitelist.

    Attributes:
        destination: The destination which has been denied
    """

    def __init__(self, destination: Optional[str]):
        """Raised by federation client or server to indicate that we are
        are deliberately not attempting to contact a given server because it is
        not on our federation whitelist.

        Args:
            destination: the domain in question
        """

        self.destination = destination

        super().__init__(
            code=403,
            msg="Federation denied with %s." % (self.destination,),
            errcode=Codes.FORBIDDEN,
        )


class InteractiveAuthIncompleteError(Exception):
    """An error raised when UI auth is not yet complete

    (This indicates we should return a 401 with 'result' as the body)

    Attributes:
        session_id: The ID of the ongoing interactive auth session.
        result: the server response to the request, which should be
            passed back to the client
    """

    def __init__(self, session_id: str, result: "JsonDict"):
        super().__init__("Interactive auth not yet complete")
        self.session_id = session_id
        self.result = result


class UnrecognizedRequestError(SynapseError):
    """An error indicating we don't understand the request you're trying to make"""

    def __init__(
        self, msg: str = "Unrecognized request", errcode: str = Codes.UNRECOGNIZED
    ):
        super().__init__(400, msg, errcode)


class NotFoundError(SynapseError):
    """An error indicating we can't find the thing you asked for"""

    def __init__(self, msg: str = "Not found", errcode: str = Codes.NOT_FOUND):
        super().__init__(404, msg, errcode=errcode)


class AuthError(SynapseError):
    """An error raised when there was a problem authorising an event, and at various
    other poorly-defined times.
    """

    def __init__(
        self,
        code: int,
        msg: str,
        errcode: str = Codes.FORBIDDEN,
        additional_fields: Optional[dict] = None,
    ):
        super().__init__(code, msg, errcode, additional_fields)


class UnstableSpecAuthError(AuthError):
    """An error raised when a new error code is being proposed to replace a previous one.
    This error will return a "org.matrix.unstable.errcode" property with the new error code,
    with the previous error code still being defined in the "errcode" property.

    This error will include `org.matrix.msc3848.unstable.errcode` in the C-S error body.
    """

    def __init__(
        self,
        code: int,
        msg: str,
        errcode: str,
        previous_errcode: str = Codes.FORBIDDEN,
        additional_fields: Optional[dict] = None,
    ):
        self.previous_errcode = previous_errcode
        super().__init__(code, msg, errcode, additional_fields)

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        fields = {}
        if config is not None and config.experimental.msc3848_enabled:
            fields["org.matrix.msc3848.unstable.errcode"] = self.errcode
        return cs_error(
            self.msg,
            self.previous_errcode,
            **fields,
            **self._additional_fields,
        )


class InvalidClientCredentialsError(SynapseError):
    """An error raised when there was a problem with the authorisation credentials
    in a client request.

    https://matrix.org/docs/spec/client_server/r0.5.0#using-access-tokens:

    When credentials are required but missing or invalid, the HTTP call will
    return with a status of 401 and the error code, M_MISSING_TOKEN or
    M_UNKNOWN_TOKEN respectively.
    """

    def __init__(self, msg: str, errcode: str):
        super().__init__(code=401, msg=msg, errcode=errcode)


class MissingClientTokenError(InvalidClientCredentialsError):
    """Raised when we couldn't find the access token in a request"""

    def __init__(self, msg: str = "Missing access token"):
        super().__init__(msg=msg, errcode="M_MISSING_TOKEN")


class InvalidClientTokenError(InvalidClientCredentialsError):
    """Raised when we didn't understand the access token in a request"""

    def __init__(
        self, msg: str = "Unrecognised access token", soft_logout: bool = False
    ):
        super().__init__(msg=msg, errcode="M_UNKNOWN_TOKEN")
        self._soft_logout = soft_logout

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        d = super().error_dict(config)
        d["soft_logout"] = self._soft_logout
        return d


class ResourceLimitError(SynapseError):
    """
    Any error raised when there is a problem with resource usage.
    For instance, the monthly active user limit for the server has been exceeded
    """

    def __init__(
        self,
        code: int,
        msg: str,
        errcode: str = Codes.RESOURCE_LIMIT_EXCEEDED,
        admin_contact: Optional[str] = None,
        limit_type: Optional[str] = None,
    ):
        self.admin_contact = admin_contact
        self.limit_type = limit_type
        super().__init__(code, msg, errcode=errcode)

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(
            self.msg,
            self.errcode,
            admin_contact=self.admin_contact,
            limit_type=self.limit_type,
        )


class EventSizeError(SynapseError):
    """An error raised when an event is too big."""

    def __init__(self, msg: str):
        super().__init__(413, msg, Codes.TOO_LARGE)


class LoginError(SynapseError):
    """An error raised when there was a problem logging in."""


class StoreError(SynapseError):
    """An error raised when there was a problem storing some data."""


class InvalidCaptchaError(SynapseError):
    def __init__(
        self,
        code: int = 400,
        msg: str = "Invalid captcha.",
        error_url: Optional[str] = None,
        errcode: str = Codes.CAPTCHA_INVALID,
    ):
        super().__init__(code, msg, errcode)
        self.error_url = error_url

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(self.msg, self.errcode, error_url=self.error_url)


class LimitExceededError(SynapseError):
    """A client has sent too many requests and is being throttled."""

    def __init__(
        self,
        code: int = 429,
        msg: str = "Too Many Requests",
        retry_after_ms: Optional[int] = None,
        errcode: str = Codes.LIMIT_EXCEEDED,
    ):
        super().__init__(code, msg, errcode)
        self.retry_after_ms = retry_after_ms

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(self.msg, self.errcode, retry_after_ms=self.retry_after_ms)


class RoomKeysVersionError(SynapseError):
    """A client has tried to upload to a non-current version of the room_keys store"""

    def __init__(self, current_version: str):
        """
        Args:
            current_version: the current version of the store they should have used
        """
        super().__init__(403, "Wrong room_keys version", Codes.WRONG_ROOM_KEYS_VERSION)
        self.current_version = current_version

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(self.msg, self.errcode, current_version=self.current_version)


class UnsupportedRoomVersionError(SynapseError):
    """The client's request to create a room used a room version that the server does
    not support."""

    def __init__(self, msg: str = "Homeserver does not support this room version"):
        super().__init__(
            code=400,
            msg=msg,
            errcode=Codes.UNSUPPORTED_ROOM_VERSION,
        )


class ThreepidValidationError(SynapseError):
    """An error raised when there was a problem authorising an event."""

    def __init__(self, msg: str, errcode: str = Codes.FORBIDDEN):
        super().__init__(400, msg, errcode)


class IncompatibleRoomVersionError(SynapseError):
    """A server is trying to join a room whose version it does not support.

    Unlike UnsupportedRoomVersionError, it is specific to the case of the make_join
    failing.
    """

    def __init__(self, room_version: str):
        super().__init__(
            code=400,
            msg="Your homeserver does not support the features required to "
            "interact with this room",
            errcode=Codes.INCOMPATIBLE_ROOM_VERSION,
        )

        self._room_version = room_version

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        return cs_error(self.msg, self.errcode, room_version=self._room_version)


class PasswordRefusedError(SynapseError):
    """A password has been refused, either during password reset/change or registration."""

    def __init__(
        self,
        msg: str = "This password doesn't comply with the server's policy",
        errcode: str = Codes.WEAK_PASSWORD,
    ):
        super().__init__(
            code=400,
            msg=msg,
            errcode=errcode,
        )


class RequestSendFailed(RuntimeError):
    """Sending a HTTP request over federation failed due to not being able to
    talk to the remote server for some reason.

    This exception is used to differentiate "expected" errors that arise due to
    networking (e.g. DNS failures, connection timeouts etc), versus unexpected
    errors (like programming errors).
    """

    def __init__(self, inner_exception: BaseException, can_retry: bool):
        super().__init__(
            "Failed to send request: %s: %s"
            % (type(inner_exception).__name__, inner_exception)
        )
        self.inner_exception = inner_exception
        self.can_retry = can_retry


class UnredactedContentDeletedError(SynapseError):
    def __init__(self, content_keep_ms: Optional[int] = None):
        super().__init__(
            404,
            "The content for that event has already been erased from the database",
            errcode=Codes.UNREDACTED_CONTENT_DELETED,
        )
        self.content_keep_ms = content_keep_ms

    def error_dict(self, config: Optional["HomeServerConfig"]) -> "JsonDict":
        extra = {}
        if self.content_keep_ms is not None:
            extra = {"fi.mau.msc2815.content_keep_ms": self.content_keep_ms}
        return cs_error(self.msg, self.errcode, **extra)


class NotApprovedError(SynapseError):
    def __init__(
        self,
        msg: str,
        approval_notice_medium: str,
    ):
        super().__init__(
            code=403,
            msg=msg,
            errcode=Codes.USER_AWAITING_APPROVAL,
            additional_fields={"approval_notice_medium": approval_notice_medium},
        )


def cs_error(msg: str, code: str = Codes.UNKNOWN, **kwargs: Any) -> "JsonDict":
    """Utility method for constructing an error response for client-server
    interactions.

    Args:
        msg: The error message.
        code: The error code.
        kwargs: Additional keys to add to the response.
    Returns:
        A dict representing the error response JSON.
    """
    err = {"error": msg, "errcode": code}
    for key, value in kwargs.items():
        err[key] = value
    return err


class FederationError(RuntimeError):
    """
    Raised when we process an erroneous PDU.

    There are two kinds of scenarios where this exception can be raised:

    1. We may pull an invalid PDU from a remote homeserver (e.g. during backfill). We
       raise this exception to signal an error to the rest of the application.
    2. We may be pushed an invalid PDU as part of a `/send` transaction from a remote
       homeserver. We raise so that we can respond to the transaction and include the
       error string in the "PDU Processing Result". The message which will likely be
       ignored by the remote homeserver and is not machine parse-able since it's just a
       string.

    TODO: In the future, we should split these usage scenarios into their own error types.

    FATAL: The remote server could not interpret the source event.
        (e.g., it was missing a required field)
    ERROR: The remote server interpreted the event, but it failed some other
        check (e.g. auth)
    WARN: The remote server accepted the event, but believes some part of it
        is wrong (e.g., it referred to an invalid event)
    """

    def __init__(
        self,
        level: str,
        code: int,
        reason: str,
        affected: str,
        source: Optional[str] = None,
    ):
        if level not in ["FATAL", "ERROR", "WARN"]:
            raise ValueError("Level is not valid: %s" % (level,))
        self.level = level
        self.code = code
        self.reason = reason
        self.affected = affected
        self.source = source

        msg = "%s %s: %s" % (level, code, reason)
        super().__init__(msg)

    def get_dict(self) -> "JsonDict":
        return {
            "level": self.level,
            "code": self.code,
            "reason": self.reason,
            "affected": self.affected,
            "source": self.source if self.source else self.affected,
        }


class FederationPullAttemptBackoffError(RuntimeError):
    """
    Raised to indicate that we are are deliberately not attempting to pull the given
    event over federation because we've already done so recently and are backing off.

    Attributes:
        event_id: The event_id which we are refusing to pull
        message: A custom error message that gives more context
    """

    def __init__(self, event_ids: List[str], message: Optional[str]):
        self.event_ids = event_ids

        if message:
            error_message = message
        else:
            error_message = f"Not attempting to pull event_ids={self.event_ids} because we already tried to pull them recently (backing off)."

        super().__init__(error_message)


class HttpResponseException(CodeMessageException):
    """
    Represents an HTTP-level failure of an outbound request

    Attributes:
        response: body of response
    """

    def __init__(self, code: int, msg: str, response: bytes):
        """

        Args:
            code: HTTP status code
            msg: reason phrase from HTTP response status line
            response: body of response
        """
        super().__init__(code, msg)
        self.response = response

    def to_synapse_error(self) -> SynapseError:
        """Make a SynapseError based on an HTTPResponseException

        This is useful when a proxied request has failed, and we need to
        decide how to map the failure onto a matrix error to send back to the
        client.

        An attempt is made to parse the body of the http response as a matrix
        error. If that succeeds, the errcode and error message from the body
        are used as the errcode and error message in the new synapse error.

        Otherwise, the errcode is set to M_UNKNOWN, and the error message is
        set to the reason code from the HTTP response.

        Returns:
            SynapseError:
        """
        # try to parse the body as json, to get better errcode/msg, but
        # default to M_UNKNOWN with the HTTP status as the error text
        try:
            j = json_decoder.decode(self.response.decode("utf-8"))
        except ValueError:
            j = {}

        if not isinstance(j, dict):
            j = {}

        errcode = j.pop("errcode", Codes.UNKNOWN)
        errmsg = j.pop("error", self.msg)

        return ProxiedRequestError(self.code, errmsg, errcode, j)


class ShadowBanError(Exception):
    """
    Raised when a shadow-banned user attempts to perform an action.

    This should be caught and a proper "fake" success response sent to the user.
    """


class ModuleFailedException(Exception):
    """
    Raised when a module API callback fails, for example because it raised an
    exception.
    """
