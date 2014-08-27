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
from synapse.types import StreamToken

import logging


logger = logging.getLogger(__name__)


class PaginationConfig(object):

    """A configuration object which stores pagination parameters."""

    def __init__(self, from_tok=None, to_tok=None, direction='f', limit=0):
        self.from_token = (
            StreamToken.from_string(from_tok) if from_tok else None
        )
        self.to_token = StreamToken.from_string(to_tok) if to_tok else None
        self.direction = 'f' if direction == 'f' else 'b'
        self.limit = int(limit)

    @classmethod
    def from_request(cls, request, raise_invalid_params=True):
        params = {
            "direction": 'f',
        }

        query_param_mappings = [  # 3-tuple of qp_key, attribute, rules
            ("from", "from_tok", lambda x: type(x) == str),
            ("to", "to_tok", lambda x: type(x) == str),
            ("limit", "limit", lambda x: x.isdigit()),
            ("dir", "direction", lambda x: x == 'f' or x == 'b'),
        ]

        for qp, attr, is_valid in query_param_mappings:
            if qp in request.args:
                if is_valid(request.args[qp][0]):
                    params[attr] = request.args[qp][0]
                elif raise_invalid_params:
                    raise SynapseError(400, "%s parameter is invalid." % qp)

        if "from_tok" in params and params["from_tok"] == "END":
            # TODO (erikj): This is for compatibility only.
            del params["from_tok"]

        try:
            return PaginationConfig(**params)
        except:
            logger.exception("Failed to create pagination config")
            raise SynapseError(400, "Invalid request.")

    def __str__(self):
        return (
            "<PaginationConfig from_tok=%s, to_tok=%s, "
            "direction=%s, limit=%s>"
        ) % (self.from_tok, self.to_tok, self.direction, self.limit)
