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


import inspect
import logging
import time
from functools import wraps
from inspect import getcallargs

from six import PY3

_TIME_FUNC_ID = 0


def _log_debug_as_f(f, msg, msg_args):
    name = f.__module__
    logger = logging.getLogger(name)

    if logger.isEnabledFor(logging.DEBUG):
        if PY3:
            lineno = f.__code__.co_firstlineno
            pathname = f.__code__.co_filename
        else:
            lineno = f.func_code.co_firstlineno
            pathname = f.func_code.co_filename

        record = logging.LogRecord(
            name=name,
            level=logging.DEBUG,
            pathname=pathname,
            lineno=lineno,
            msg=msg,
            args=msg_args,
            exc_info=None,
        )

        logger.handle(record)


def log_function(f):
    """ Function decorator that logs every call to that function.
    """
    func_name = f.__name__

    @wraps(f)
    def wrapped(*args, **kwargs):
        name = f.__module__
        logger = logging.getLogger(name)
        level = logging.DEBUG

        if logger.isEnabledFor(level):
            bound_args = getcallargs(f, *args, **kwargs)

            def format(value):
                r = str(value)
                if len(r) > 50:
                    r = r[:50] + "..."
                return r

            func_args = ["%s=%s" % (k, format(v)) for k, v in bound_args.items()]

            msg_args = {"func_name": func_name, "args": ", ".join(func_args)}

            _log_debug_as_f(f, "Invoked '%(func_name)s' with args: %(args)s", msg_args)

        return f(*args, **kwargs)

    wrapped.__name__ = func_name
    return wrapped


def time_function(f):
    func_name = f.__name__

    @wraps(f)
    def wrapped(*args, **kwargs):
        global _TIME_FUNC_ID
        id = _TIME_FUNC_ID
        _TIME_FUNC_ID += 1

        start = time.clock()

        try:
            _log_debug_as_f(f, "[FUNC START] {%s-%d}", (func_name, id))

            r = f(*args, **kwargs)
        finally:
            end = time.clock()
            _log_debug_as_f(
                f, "[FUNC END] {%s-%d} %.3f sec", (func_name, id, end - start)
            )

        return r

    return wrapped


def trace_function(f):
    func_name = f.__name__
    linenum = f.func_code.co_firstlineno
    pathname = f.func_code.co_filename

    @wraps(f)
    def wrapped(*args, **kwargs):
        name = f.__module__
        logger = logging.getLogger(name)
        level = logging.DEBUG

        s = inspect.currentframe().f_back

        to_print = [
            "\t%s:%s %s. Args: args=%s, kwargs=%s"
            % (pathname, linenum, func_name, args, kwargs)
        ]
        while s:
            if True or s.f_globals["__name__"].startswith("synapse"):
                filename, lineno, function, _, _ = inspect.getframeinfo(s)
                args_string = inspect.formatargvalues(*inspect.getargvalues(s))

                to_print.append(
                    "\t%s:%d %s. Args: %s" % (filename, lineno, function, args_string)
                )

            s = s.f_back

        msg = "\nTraceback for %s:\n" % (func_name,) + "\n".join(to_print)

        record = logging.LogRecord(
            name=name,
            level=level,
            pathname=pathname,
            lineno=lineno,
            msg=msg,
            args=None,
            exc_info=None,
        )

        logger.handle(record)

        return f(*args, **kwargs)

    wrapped.__name__ = func_name
    return wrapped


def get_previous_frames():
    s = inspect.currentframe().f_back.f_back
    to_return = []
    while s:
        if s.f_globals["__name__"].startswith("synapse"):
            filename, lineno, function, _, _ = inspect.getframeinfo(s)
            args_string = inspect.formatargvalues(*inspect.getargvalues(s))

            to_return.append(
                "{{  %s:%d %s - Args: %s }}" % (filename, lineno, function, args_string)
            )

        s = s.f_back

    return ", ".join(to_return)


def get_previous_frame(ignore=[]):
    s = inspect.currentframe().f_back.f_back

    while s:
        if s.f_globals["__name__"].startswith("synapse"):
            if not any(s.f_globals["__name__"].startswith(ig) for ig in ignore):
                filename, lineno, function, _, _ = inspect.getframeinfo(s)
                args_string = inspect.formatargvalues(*inspect.getargvalues(s))

                return "{{  %s:%d %s - Args: %s }}" % (
                    filename,
                    lineno,
                    function,
                    args_string,
                )

        s = s.f_back

    return None
