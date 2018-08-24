# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd.
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

from six import iteritems
from six.moves import http_client

from canonicaljson import json

logger = logging.getLogger(__name__)


class Codes(object):
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


class CodeMessageException(RuntimeError):
    """An exception with integer code and message string attributes.

    Attributes:
        code (int): HTTP error code
        msg (str): string describing the error
    """
    def __init__(self, code, msg):
        super(CodeMessageException, self).__init__("%d: %s" % (code, msg))
        self.code = code
        self.msg = msg


class SynapseError(CodeMessageException):
    """A base exception type for matrix errors which have an errcode and error
    message (as well as an HTTP status code).

    Attributes:
        errcode (str): Matrix error code e.g 'M_FORBIDDEN'
    """
    def __init__(self, code, msg, errcode=Codes.UNKNOWN):
        """Constructs a synapse error.

        Args:
            code (int): The integer error code (an HTTP response code)
            msg (str): The human-readable error message.
            errcode (str): The matrix error code e.g 'M_FORBIDDEN'
        """
        super(SynapseError, self).__init__(code, msg)
        self.errcode = errcode

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
        )


class ProxiedRequestError(SynapseError):
    """An error from a general matrix endpoint, eg. from a proxied Matrix API call.

    Attributes:
        errcode (str): Matrix error code e.g 'M_FORBIDDEN'
    """
    def __init__(self, code, msg, errcode=Codes.UNKNOWN, additional_fields=None):
        super(ProxiedRequestError, self).__init__(
            code, msg, errcode
        )
        if additional_fields is None:
            self._additional_fields = {}
        else:
            self._additional_fields = dict(additional_fields)

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            **self._additional_fields
        )


class ConsentNotGivenError(SynapseError):
    """The error returned to the client when the user has not consented to the
    privacy policy.
    """
    def __init__(self, msg, consent_uri):
        """Constructs a ConsentNotGivenError

        Args:
            msg (str): The human-readable error message
            consent_url (str): The URL where the user can give their consent
        """
        super(ConsentNotGivenError, self).__init__(
            code=http_client.FORBIDDEN,
            msg=msg,
            errcode=Codes.CONSENT_NOT_GIVEN
        )
        self._consent_uri = consent_uri

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            consent_uri=self._consent_uri
        )


class RegistrationError(SynapseError):
    """An error raised when a registration event fails."""
    pass


class FederationDeniedError(SynapseError):
    """An error raised when the server tries to federate with a server which
    is not on its federation whitelist.

    Attributes:
        destination (str): The destination which has been denied
    """

    def __init__(self, destination):
        """Raised by federation client or server to indicate that we are
        are deliberately not attempting to contact a given server because it is
        not on our federation whitelist.

        Args:
            destination (str): the domain in question
        """

        self.destination = destination

        super(FederationDeniedError, self).__init__(
            code=403,
            msg="Federation denied with %s." % (self.destination,),
            errcode=Codes.FORBIDDEN,
        )


class InteractiveAuthIncompleteError(Exception):
    """An error raised when UI auth is not yet complete

    (This indicates we should return a 401 with 'result' as the body)

    Attributes:
        result (dict): the server response to the request, which should be
            passed back to the client
    """
    def __init__(self, result):
        super(InteractiveAuthIncompleteError, self).__init__(
            "Interactive auth not yet complete",
        )
        self.result = result


class UnrecognizedRequestError(SynapseError):
    """An error indicating we don't understand the request you're trying to make"""
    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.UNRECOGNIZED
        message = None
        if len(args) == 0:
            message = "Unrecognized request"
        else:
            message = args[0]
        super(UnrecognizedRequestError, self).__init__(
            400,
            message,
            **kwargs
        )


class NotFoundError(SynapseError):
    """An error indicating we can't find the thing you asked for"""
    def __init__(self, msg="Not found", errcode=Codes.NOT_FOUND):
        super(NotFoundError, self).__init__(
            404,
            msg,
            errcode=errcode
        )


class AuthError(SynapseError):
    """An error raised when there was a problem authorising an event."""

    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.FORBIDDEN
        super(AuthError, self).__init__(*args, **kwargs)


class ResourceLimitError(SynapseError):
    """
    Any error raised when there is a problem with resource usage.
    For instance, the monthly active user limit for the server has been exceeded
    """
    def __init__(
        self, code, msg,
        errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
        admin_contact=None,
        limit_type=None,
    ):
        self.admin_contact = admin_contact
        self.limit_type = limit_type
        super(ResourceLimitError, self).__init__(code, msg, errcode=errcode)

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            admin_contact=self.admin_contact,
            limit_type=self.limit_type
        )


class EventSizeError(SynapseError):
    """An error raised when an event is too big."""

    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.TOO_LARGE
        super(EventSizeError, self).__init__(413, *args, **kwargs)


class EventStreamError(SynapseError):
    """An error raised when there a problem with the event stream."""
    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.BAD_PAGINATION
        super(EventStreamError, self).__init__(*args, **kwargs)


class LoginError(SynapseError):
    """An error raised when there was a problem logging in."""
    pass


class StoreError(SynapseError):
    """An error raised when there was a problem storing some data."""
    pass


class InvalidCaptchaError(SynapseError):
    def __init__(self, code=400, msg="Invalid captcha.", error_url=None,
                 errcode=Codes.CAPTCHA_INVALID):
        super(InvalidCaptchaError, self).__init__(code, msg, errcode)
        self.error_url = error_url

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            error_url=self.error_url,
        )


class LimitExceededError(SynapseError):
    """A client has sent too many requests and is being throttled.
    """
    def __init__(self, code=429, msg="Too Many Requests", retry_after_ms=None,
                 errcode=Codes.LIMIT_EXCEEDED):
        super(LimitExceededError, self).__init__(code, msg, errcode)
        self.retry_after_ms = retry_after_ms

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            retry_after_ms=self.retry_after_ms,
        )


class IncompatibleRoomVersionError(SynapseError):
    """A server is trying to join a room whose version it does not support."""

    def __init__(self, room_version):
        super(IncompatibleRoomVersionError, self).__init__(
            code=400,
            msg="Your homeserver does not support the features required to "
                "join this room",
            errcode=Codes.INCOMPATIBLE_ROOM_VERSION,
        )

        self._room_version = room_version

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            room_version=self._room_version,
        )


def cs_error(msg, code=Codes.UNKNOWN, **kwargs):
    """ Utility method for constructing an error response for client-server
    interactions.

    Args:
        msg (str): The error message.
        code (str): The error code.
        kwargs : Additional keys to add to the response.
    Returns:
        A dict representing the error response JSON.
    """
    err = {"error": msg, "errcode": code}
    for key, value in iteritems(kwargs):
        err[key] = value
    return err


class FederationError(RuntimeError):
    """  This class is used to inform remote home servers about erroneous
    PDUs they sent us.

    FATAL: The remote server could not interpret the source event.
        (e.g., it was missing a required field)
    ERROR: The remote server interpreted the event, but it failed some other
        check (e.g. auth)
    WARN: The remote server accepted the event, but believes some part of it
        is wrong (e.g., it referred to an invalid event)
    """

    def __init__(self, level, code, reason, affected, source=None):
        if level not in ["FATAL", "ERROR", "WARN"]:
            raise ValueError("Level is not valid: %s" % (level,))
        self.level = level
        self.code = code
        self.reason = reason
        self.affected = affected
        self.source = source

        msg = "%s %s: %s" % (level, code, reason,)
        super(FederationError, self).__init__(msg)

    def get_dict(self):
        return {
            "level": self.level,
            "code": self.code,
            "reason": self.reason,
            "affected": self.affected,
            "source": self.source if self.source else self.affected,
        }


class HttpResponseException(CodeMessageException):
    """
    Represents an HTTP-level failure of an outbound request

    Attributes:
        response (bytes): body of response
    """
    def __init__(self, code, msg, response):
        """

        Args:
            code (int): HTTP status code
            msg (str): reason phrase from HTTP response status line
            response (bytes): body of response
        """
        super(HttpResponseException, self).__init__(code, msg)
        self.response = response

    def to_synapse_error(self):
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
            j = json.loads(self.response)
        except ValueError:
            j = {}

        if not isinstance(j, dict):
            j = {}

        errcode = j.pop('errcode', Codes.UNKNOWN)
        errmsg = j.pop('error', self.msg)

        return ProxiedRequestError(self.code, errmsg, errcode, j)
