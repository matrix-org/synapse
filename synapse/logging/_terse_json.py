# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

"""
Log formatters that output terse JSON.
"""
import json
import logging
from typing import Optional

_encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))


class TerseJsonFormatter:
    def __init__(
        self, *args, include_time: bool = True, metadata: Optional[dict] = None
    ):
        self.include_time = include_time
        self.metadata = metadata or {}

    def format(self, record: logging.LogRecord) -> str:
        event = {
            "log": record.getMessage(),
            "namespace": record.name,
            "level": record.levelname,
        }

        # We want to include the timestamp when forwarding over the network, but
        # exclude it when we are writing to stdout. This is because the log ingester
        # (e.g. logstash, fluentd) can add its own timestamp.
        if self.include_time:
            event["time"] = round(record.created, 2)

        # Add the metadata information to the event (e.g. the server_name).
        event.update(self.metadata)

        return _encoder.encode(event)
