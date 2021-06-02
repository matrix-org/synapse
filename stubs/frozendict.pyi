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

# Stub for frozendict.

from typing import Any, Hashable, Iterable, Iterator, Mapping, Tuple, TypeVar, overload

_KT = TypeVar("_KT", bound=Hashable)  # Key type.
_VT = TypeVar("_VT")  # Value type.

class frozendict(Mapping[_KT, _VT]):
    @overload
    def __init__(self, **kwargs: _VT) -> None: ...
    @overload
    def __init__(self, __map: Mapping[_KT, _VT], **kwargs: _VT) -> None: ...
    @overload
    def __init__(
        self, __iterable: Iterable[Tuple[_KT, _VT]], **kwargs: _VT
    ) -> None: ...
    def __getitem__(self, key: _KT) -> _VT: ...
    def __contains__(self, key: Any) -> bool: ...
    def copy(self, **add_or_replace: Any) -> frozendict: ...
    def __iter__(self) -> Iterator[_KT]: ...
    def __len__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...
