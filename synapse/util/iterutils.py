# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from itertools import islice
from typing import Iterable, Iterator, Sequence, Tuple, TypeVar

T = TypeVar("T")


def batch_iter(iterable: Iterable[T], size: int) -> Iterator[Tuple[T]]:
    """batch an iterable up into tuples with a maximum size

    Args:
        iterable (iterable): the iterable to slice
        size (int): the maximum batch size

    Returns:
        an iterator over the chunks
    """
    # make sure we can deal with iterables like lists too
    sourceiter = iter(iterable)
    # call islice until it returns an empty tuple
    return iter(lambda: tuple(islice(sourceiter, size)), ())


ISeq = TypeVar("ISeq", bound=Sequence, covariant=True)


def chunk_seq(iseq: ISeq, maxlen: int) -> Iterable[ISeq]:
    """Split the given sequence into chunks of the given size

    The last chunk may be shorter than the given size.

    If the input is empty, no chunks are returned.
    """
    return (iseq[i : i + maxlen] for i in range(0, len(iseq), maxlen))
