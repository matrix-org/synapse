# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Tuple


class TestHtmlParser(HTMLParser):
    """A generic HTML page parser which extracts useful things from the HTML"""

    def __init__(self):
        super().__init__()

        # a list of links found in the doc
        self.links: List[str] = []

        # the values of any hidden <input>s: map from name to value
        self.hiddens: Dict[str, Optional[str]] = {}

        # the values of any radio buttons: map from name to list of values
        self.radios: Dict[str, List[Optional[str]]] = {}

    def handle_starttag(
        self, tag: str, attrs: Iterable[Tuple[str, Optional[str]]]
    ) -> None:
        attr_dict = dict(attrs)
        if tag == "a":
            href = attr_dict["href"]
            if href:
                self.links.append(href)
        elif tag == "input":
            input_name = attr_dict.get("name")
            if attr_dict["type"] == "radio":
                assert input_name
                self.radios.setdefault(input_name, []).append(attr_dict["value"])
            elif attr_dict["type"] == "hidden":
                assert input_name
                self.hiddens[input_name] = attr_dict["value"]

    def error(_, message):
        raise AssertionError(message)
