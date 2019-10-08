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
Tools for generating "human readable" IDs to aid in debugging.
"""

import os
import random as _badrandom
from typing import List

_rand = _badrandom.SystemRandom()


class IDGenerator(object):
    """
    A human-readable ID generator.
    """

    def __init__(self, files=None, digits=1):
        base = os.path.split(__file__)[0]
        self.digits = digits
        self._sections = []  # type: List[List[str]]

        if files:
            for wordlist in files:
                with open(os.path.join(base, wordlist), "r") as f:
                    self._sections.append(f.read().split("\n"))

    def next(self):

        out = []

        if self._sections:
            for section in self._sections:
                out.append(_rand.choice(section))

        for i in range(self.digits):
            out.append(str(_rand.randint(1, 999)))

        return "-".join(out)

    def __call__(self):
        return self.next()


readable_id = IDGenerator(["colors.txt", "birds.txt"])
