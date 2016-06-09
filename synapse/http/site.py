# Copyright 2016 OpenMarket Ltd
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

from synapse.util.logcontext import LoggingContext
from twisted.web.server import Site, Request

import contextlib
import logging
import re
import time

ACCESS_TOKEN_RE = re.compile(r'(\?.*access(_|%5[Ff])token=)[^&]*(.*)$')


class SynapseRequest(Request):
    def __init__(self, site, *args, **kw):
        Request.__init__(self, *args, **kw)
        self.site = site
        self.authenticated_entity = None
        self.start_time = 0

    def __repr__(self):
        # We overwrite this so that we don't log ``access_token``
        return '<%s at 0x%x method=%s uri=%s clientproto=%s site=%s>' % (
            self.__class__.__name__,
            id(self),
            self.method,
            self.get_redacted_uri(),
            self.clientproto,
            self.site.site_tag,
        )

    def get_redacted_uri(self):
        return ACCESS_TOKEN_RE.sub(
            r'\1<redacted>\3',
            self.uri
        )

    def get_user_agent(self):
        return self.requestHeaders.getRawHeaders("User-Agent", [None])[-1]

    def started_processing(self):
        self.site.access_logger.info(
            "%s - %s - Received request: %s %s",
            self.getClientIP(),
            self.site.site_tag,
            self.method,
            self.get_redacted_uri()
        )
        self.start_time = int(time.time() * 1000)

    def finished_processing(self):

        try:
            context = LoggingContext.current_context()
            ru_utime, ru_stime = context.get_resource_usage()
            db_txn_count = context.db_txn_count
            db_txn_duration = context.db_txn_duration
        except:
            ru_utime, ru_stime = (0, 0)
            db_txn_count, db_txn_duration = (0, 0)

        self.site.access_logger.info(
            "%s - %s - {%s}"
            " Processed request: %dms (%dms, %dms) (%dms/%d)"
            " %sB %s \"%s %s %s\" \"%s\"",
            self.getClientIP(),
            self.site.site_tag,
            self.authenticated_entity,
            int(time.time() * 1000) - self.start_time,
            int(ru_utime * 1000),
            int(ru_stime * 1000),
            int(db_txn_duration * 1000),
            int(db_txn_count),
            self.sentLength,
            self.code,
            self.method,
            self.get_redacted_uri(),
            self.clientproto,
            self.get_user_agent(),
        )

    @contextlib.contextmanager
    def processing(self):
        self.started_processing()
        yield
        self.finished_processing()


class XForwardedForRequest(SynapseRequest):
    def __init__(self, *args, **kw):
        SynapseRequest.__init__(self, *args, **kw)

    """
    Add a layer on top of another request that only uses the value of an
    X-Forwarded-For header as the result of C{getClientIP}.
    """
    def getClientIP(self):
        """
        @return: The client address (the first address) in the value of the
            I{X-Forwarded-For header}.  If the header is not present, return
            C{b"-"}.
        """
        return self.requestHeaders.getRawHeaders(
            b"x-forwarded-for", [b"-"])[0].split(b",")[0].strip()


class SynapseRequestFactory(object):
    def __init__(self, site, x_forwarded_for):
        self.site = site
        self.x_forwarded_for = x_forwarded_for

    def __call__(self, *args, **kwargs):
        if self.x_forwarded_for:
            return XForwardedForRequest(self.site, *args, **kwargs)
        else:
            return SynapseRequest(self.site, *args, **kwargs)


class SynapseSite(Site):
    """
    Subclass of a twisted http Site that does access logging with python's
    standard logging
    """
    def __init__(self, logger_name, site_tag, config, resource, *args, **kwargs):
        Site.__init__(self, resource, *args, **kwargs)

        self.site_tag = site_tag

        proxied = config.get("x_forwarded", False)
        self.requestFactory = SynapseRequestFactory(self, proxied)
        self.access_logger = logging.getLogger(logger_name)

    def log(self, request):
        pass
