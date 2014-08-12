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
from synapse.api.errors import SynapseError


class PaginationConfig(object):

    """A configuration object which stores pagination parameters."""

    def __init__(self, from_tok=None, to_tok=None, limit=0):
        self.from_tok = from_tok
        self.to_tok = to_tok
        self.limit = limit

    @classmethod
    def from_request(cls, request, raise_invalid_params=True):
        params = {
            "from_tok": PaginationStream.TOK_START,
            "to_tok": PaginationStream.TOK_END,
            "limit": 0
        }

        query_param_mappings = [  # 3-tuple of qp_key, attribute, rules
            ("from", "from_tok", lambda x: type(x) == str),
            ("to", "to_tok", lambda x: type(x) == str),
            ("limit", "limit", lambda x: x.isdigit())
        ]

        for qp, attr, is_valid in query_param_mappings:
            if qp in request.args:
                if is_valid(request.args[qp][0]):
                    params[attr] = request.args[qp][0]
                elif raise_invalid_params:
                    raise SynapseError(400, "%s parameter is invalid." % qp)

        return PaginationConfig(**params)


class PaginationStream(object):

    """ An interface for streaming data as chunks. """

    TOK_START = "START"
    TOK_END = "END"

    def get_chunk(self, config=None):
        """ Return the next chunk in the stream.

        Args:
            config (PaginationConfig): The config to aid which chunk to get.
        Returns:
            A dict containing the new start token "start", the new end token
            "end" and the data "chunk" as a list.
        """
        raise NotImplementedError()


class StreamData(object):

    """ An interface for obtaining streaming data from a table. """

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()

    def get_rows(self, user_id, from_pkey, to_pkey, limit):
        """ Get event stream data between the specified pkeys.

        Args:
            user_id : The user's ID
            from_pkey : The starting pkey.
            to_pkey : The end pkey. May be -1 to mean "latest".
            limit: The max number of results to return.
        Returns:
            A tuple containing the list of event stream data and the last pkey.
        """
        raise NotImplementedError()

    def max_token(self):
        """ Get the latest currently-valid token.

        Returns:
            The latest token."""
        raise NotImplementedError()
