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

from inspect import getcallargs

import logging


def log_function(f):
    """ Function decorator that logs every call to that function.
    """
    func_name = f.__name__
    lineno = f.func_code.co_firstlineno
    pathname = f.func_code.co_filename

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

            func_args = [
                "%s=%s" % (k, format(v)) for k, v in bound_args.items()
            ]

            msg_args = {
                "func_name": func_name,
                "args": ", ".join(func_args)
            }

            record = logging.LogRecord(
                name=name,
                level=level,
                pathname=pathname,
                lineno=lineno,
                msg="Invoked '%(func_name)s' with args: %(args)s",
                args=msg_args,
                exc_info=None
            )

            logger.handle(record)

        return f(*args, **kwargs)

    return wrapped
