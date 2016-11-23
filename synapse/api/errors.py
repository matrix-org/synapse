# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
    INVALID_USERNAME = "M_INVALID_USERNAME"
    SERVER_NOT_TRUSTED = "M_SERVER_NOT_TRUSTED"


class CodeMessageException(RuntimeError):
    """An exception with integer code and message string attributes."""

    def __init__(self, code, msg):
        super(CodeMessageException, self).__init__("%d: %s" % (code, msg))
        self.code = code
        self.msg = msg
        self.response_code_message = None

    def error_dict(self):
        return cs_error(self.msg)


class SynapseError(CodeMessageException):
    """A base error which can be caught for all synapse events."""
    def __init__(self, code, msg, errcode=Codes.UNKNOWN):
        """Constructs a synapse error.

        Args:
            code (int): The integer error code (an HTTP response code)
            msg (str): The human-readable error message.
            err (str): The error code e.g 'M_FORBIDDEN'
        """
        super(SynapseError, self).__init__(code, msg)
        self.errcode = errcode

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
        )


class RegistrationError(SynapseError):
    """An error raised when a registration event fails."""
    pass


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
    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.NOT_FOUND
        super(NotFoundError, self).__init__(
            404,
            "Not found",
            **kwargs
        )


class AuthError(SynapseError):
    """An error raised when there was a problem authorising an event."""

    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.FORBIDDEN
        super(AuthError, self).__init__(*args, **kwargs)


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
        self.response_code_message = "Too Many Requests"

    def error_dict(self):
        return cs_error(
            self.msg,
            self.errcode,
            retry_after_ms=self.retry_after_ms,
        )


def cs_exception(exception):
    if isinstance(exception, CodeMessageException):
        return exception.error_dict()
    else:
        logger.error("Unknown exception type: %s", type(exception))
        return {}


def cs_error(msg, code=Codes.UNKNOWN, **kwargs):
    """ Utility method for constructing an error response for client-server
    interactions.

    Args:
        msg (str): The error message.
        code (int): The error code.
        kwargs : Additional keys to add to the response.
    Returns:
        A dict representing the error response JSON.
    """
    err = {"error": msg, "errcode": code}
    for key, value in kwargs.iteritems():
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
    def __init__(self, code, msg, response):
        self.response = response
        super(HttpResponseException, self).__init__(code, msg)
