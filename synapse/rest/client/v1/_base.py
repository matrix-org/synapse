# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation C.I.C
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

from synapse.rest.client.v2_alpha._base import client_patterns as _client_patterns


def client_patterns(*args, **kwargs):
    """
    A client_patterns creator that enables v1 for APIs.
    """
    if "v1" in kwargs:
        del kwargs["v1"]
    return _client_patterns(*args, v1=True, **kwargs)


__all__ = ["client_patterns"]
