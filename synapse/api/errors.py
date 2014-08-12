# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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


class Codes(object):
    FORBIDDEN = "M_FORBIDDEN"
    BAD_JSON = "M_BAD_JSON"
    NOT_JSON = "M_NOT_JSON"
    USER_IN_USE = "M_USER_IN_USE"
    ROOM_IN_USE = "M_ROOM_IN_USE"
    BAD_PAGINATION = "M_BAD_PAGINATION"
    UNKNOWN = "M_UNKNOWN"
    NOT_FOUND = "M_NOT_FOUND"


class CodeMessageException(Exception):
    """An exception with integer code and message string attributes."""

    def __init__(self, code, msg):
        logging.error("%s: %s, %s", type(self).__name__, code, msg)
        super(CodeMessageException, self).__init__("%d: %s" % (code, msg))
        self.code = code
        self.msg = msg


class SynapseError(CodeMessageException):
    """A base error which can be caught for all synapse events."""
    def __init__(self, code, msg, errcode=""):
        """Constructs a synapse error.

        Args:
            code (int): The integer error code (typically an HTTP response code)
            msg (str): The human-readable error message.
            err (str): The error code e.g 'M_FORBIDDEN'
        """
        super(SynapseError, self).__init__(code, msg)
        self.errcode = errcode


class RoomError(SynapseError):
    """An error raised when a room event fails."""
    pass


class RegistrationError(SynapseError):
    """An error raised when a registration event fails."""
    pass


class AuthError(SynapseError):
    """An error raised when there was a problem authorising an event."""

    def __init__(self, *args, **kwargs):
        if "errcode" not in kwargs:
            kwargs["errcode"] = Codes.FORBIDDEN
        super(AuthError, self).__init__(*args, **kwargs)


class EventStreamError(SynapseError):
    """An error raised when there a problem with the event stream."""
    pass


class LoginError(SynapseError):
    """An error raised when there was a problem logging in."""
    pass


class StoreError(SynapseError):
    """An error raised when there was a problem storing some data."""
    pass


def cs_exception(exception):
    if isinstance(exception, SynapseError):
        return cs_error(
            exception.msg,
            Codes.UNKNOWN if not exception.errcode else exception.errcode)
    elif isinstance(exception, CodeMessageException):
        return cs_error(exception.msg)
    else:
        logging.error("Unknown exception type: %s", type(exception))


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
