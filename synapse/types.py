# Copyright 2014-2016 OpenMarket Ltd
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
import abc
import re
import string
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Dict,
    List,
    Mapping,
    Match,
    MutableMapping,
    NoReturn,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
)

import attr
from frozendict import frozendict
from signedjson.key import decode_verify_key_bytes
from signedjson.types import VerifyKey
from typing_extensions import Final, TypedDict
from unpaddedbase64 import decode_base64
from zope.interface import Interface

from twisted.internet.defer import CancelledError
from twisted.internet.interfaces import (
    IReactorCore,
    IReactorPluggableNameResolver,
    IReactorSSL,
    IReactorTCP,
    IReactorThreads,
    IReactorTime,
)

from synapse.api.errors import Codes, SynapseError
from synapse.util.cancellation import cancellable
from synapse.util.stringutils import parse_and_validate_server_name

if TYPE_CHECKING:
    from synapse.appservice.api import ApplicationService
    from synapse.storage.databases.main import DataStore, PurgeEventsStore
    from synapse.storage.databases.main.appservice import ApplicationServiceWorkerStore

# Define a state map type from type/state_key to T (usually an event ID or
# event)
T = TypeVar("T")
StateKey = Tuple[str, str]
StateMap = Mapping[StateKey, T]
MutableStateMap = MutableMapping[StateKey, T]

# JSON types. These could be made stronger, but will do for now.
# A JSON-serialisable dict.
JsonDict = Dict[str, Any]
# A JSON-serialisable mapping; roughly speaking an immutable JSONDict.
# Useful when you have a TypedDict which isn't going to be mutated and you don't want
# to cast to JsonDict everywhere.
JsonMapping = Mapping[str, Any]
# A JSON-serialisable object.
JsonSerializable = object


# Note that this seems to require inheriting *directly* from Interface in order
# for mypy-zope to realize it is an interface.
class ISynapseReactor(
    IReactorTCP,
    IReactorSSL,
    IReactorPluggableNameResolver,
    IReactorTime,
    IReactorCore,
    IReactorThreads,
    Interface,
):
    """The interfaces necessary for Synapse to function."""


@attr.s(frozen=True, slots=True, auto_attribs=True)
class Requester:
    """
    Represents the user making a request

    Attributes:
        user:  id of the user making the request
        access_token_id:  *ID* of the access token used for this
            request, or None if it came via the appservice API or similar
        is_guest:  True if the user making this request is a guest user
        shadow_banned:  True if the user making this request has been shadow-banned.
        device_id:  device_id which was set at authentication time
        app_service:  the AS requesting on behalf of the user
        authenticated_entity: The entity that authenticated when making the request.
            This is different to the user_id when an admin user or the server is
            "puppeting" the user.
    """

    user: "UserID"
    access_token_id: Optional[int]
    is_guest: bool
    shadow_banned: bool
    device_id: Optional[str]
    app_service: Optional["ApplicationService"]
    authenticated_entity: str

    def serialize(self) -> Dict[str, Any]:
        """Converts self to a type that can be serialized as JSON, and then
        deserialized by `deserialize`

        Returns:
            dict
        """
        return {
            "user_id": self.user.to_string(),
            "access_token_id": self.access_token_id,
            "is_guest": self.is_guest,
            "shadow_banned": self.shadow_banned,
            "device_id": self.device_id,
            "app_server_id": self.app_service.id if self.app_service else None,
            "authenticated_entity": self.authenticated_entity,
        }

    @staticmethod
    def deserialize(
        store: "ApplicationServiceWorkerStore", input: Dict[str, Any]
    ) -> "Requester":
        """Converts a dict that was produced by `serialize` back into a
        Requester.

        Args:
            store (DataStore): Used to convert AS ID to AS object
            input (dict): A dict produced by `serialize`

        Returns:
            Requester
        """
        appservice = None
        if input["app_server_id"]:
            appservice = store.get_app_service_by_id(input["app_server_id"])

        return Requester(
            user=UserID.from_string(input["user_id"]),
            access_token_id=input["access_token_id"],
            is_guest=input["is_guest"],
            shadow_banned=input["shadow_banned"],
            device_id=input["device_id"],
            app_service=appservice,
            authenticated_entity=input["authenticated_entity"],
        )


def create_requester(
    user_id: Union[str, "UserID"],
    access_token_id: Optional[int] = None,
    is_guest: bool = False,
    shadow_banned: bool = False,
    device_id: Optional[str] = None,
    app_service: Optional["ApplicationService"] = None,
    authenticated_entity: Optional[str] = None,
) -> Requester:
    """
    Create a new ``Requester`` object

    Args:
        user_id:  id of the user making the request
        access_token_id:  *ID* of the access token used for this
            request, or None if it came via the appservice API or similar
        is_guest:  True if the user making this request is a guest user
        shadow_banned:  True if the user making this request is shadow-banned.
        device_id:  device_id which was set at authentication time
        app_service:  the AS requesting on behalf of the user
        authenticated_entity: The entity that authenticated when making the request.
            This is different to the user_id when an admin user or the server is
            "puppeting" the user.

    Returns:
        Requester
    """
    if not isinstance(user_id, UserID):
        user_id = UserID.from_string(user_id)

    if authenticated_entity is None:
        authenticated_entity = user_id.to_string()

    return Requester(
        user_id,
        access_token_id,
        is_guest,
        shadow_banned,
        device_id,
        app_service,
        authenticated_entity,
    )


def get_domain_from_id(string: str) -> str:
    idx = string.find(":")
    if idx == -1:
        raise SynapseError(400, "Invalid ID: %r" % (string,))
    return string[idx + 1 :]


def get_localpart_from_id(string: str) -> str:
    idx = string.find(":")
    if idx == -1:
        raise SynapseError(400, "Invalid ID: %r" % (string,))
    return string[1:idx]


DS = TypeVar("DS", bound="DomainSpecificString")


@attr.s(slots=True, frozen=True, repr=False, auto_attribs=True)
class DomainSpecificString(metaclass=abc.ABCMeta):
    """Common base class among ID/name strings that have a local part and a
    domain name, prefixed with a sigil.

    Has the fields:

        'localpart' : The local part of the name (without the leading sigil)
        'domain' : The domain part of the name
    """

    SIGIL: ClassVar[str] = abc.abstractproperty()  # type: ignore

    localpart: str
    domain: str

    # Because this is a frozen class, it is deeply immutable.
    def __copy__(self: DS) -> DS:
        return self

    def __deepcopy__(self: DS, memo: Dict[str, object]) -> DS:
        return self

    @classmethod
    def from_string(cls: Type[DS], s: str) -> DS:
        """Parse the string given by 's' into a structure object."""
        if len(s) < 1 or s[0:1] != cls.SIGIL:
            raise SynapseError(
                400,
                "Expected %s string to start with '%s'" % (cls.__name__, cls.SIGIL),
                Codes.INVALID_PARAM,
            )

        parts = s[1:].split(":", 1)
        if len(parts) != 2:
            raise SynapseError(
                400,
                "Expected %s of the form '%slocalname:domain'"
                % (cls.__name__, cls.SIGIL),
                Codes.INVALID_PARAM,
            )

        domain = parts[1]
        # This code will need changing if we want to support multiple domain
        # names on one HS
        return cls(localpart=parts[0], domain=domain)

    def to_string(self) -> str:
        """Return a string encoding the fields of the structure object."""
        return "%s%s:%s" % (self.SIGIL, self.localpart, self.domain)

    @classmethod
    def is_valid(cls: Type[DS], s: str) -> bool:
        """Parses the input string and attempts to ensure it is valid."""
        # TODO: this does not reject an empty localpart or an overly-long string.
        # See https://spec.matrix.org/v1.2/appendices/#identifier-grammar
        try:
            obj = cls.from_string(s)
            # Apply additional validation to the domain. This is only done
            # during  is_valid (and not part of from_string) since it is
            # possible for invalid data to exist in room-state, etc.
            parse_and_validate_server_name(obj.domain)
            return True
        except Exception:
            return False

    __repr__ = to_string


@attr.s(slots=True, frozen=True, repr=False)
class UserID(DomainSpecificString):
    """Structure representing a user ID."""

    SIGIL = "@"


@attr.s(slots=True, frozen=True, repr=False)
class RoomAlias(DomainSpecificString):
    """Structure representing a room name."""

    SIGIL = "#"


@attr.s(slots=True, frozen=True, repr=False)
class RoomID(DomainSpecificString):
    """Structure representing a room id."""

    SIGIL = "!"


@attr.s(slots=True, frozen=True, repr=False)
class EventID(DomainSpecificString):
    """Structure representing an event id."""

    SIGIL = "$"


mxid_localpart_allowed_characters = set(
    "_-./=" + string.ascii_lowercase + string.digits
)


def contains_invalid_mxid_characters(localpart: str) -> bool:
    """Check for characters not allowed in an mxid or groupid localpart

    Args:
        localpart: the localpart to be checked

    Returns:
        True if there are any naughty characters
    """
    return any(c not in mxid_localpart_allowed_characters for c in localpart)


UPPER_CASE_PATTERN = re.compile(b"[A-Z_]")

# the following is a pattern which matches '=', and bytes which are not allowed in a mxid
# localpart.
#
# It works by:
#  * building a string containing the allowed characters (excluding '=')
#  * escaping every special character with a backslash (to stop '-' being interpreted as a
#    range operator)
#  * wrapping it in a '[^...]' regex
#  * converting the whole lot to a 'bytes' sequence, so that we can use it to match
#    bytes rather than strings
#
NON_MXID_CHARACTER_PATTERN = re.compile(
    ("[^%s]" % (re.escape("".join(mxid_localpart_allowed_characters - {"="})),)).encode(
        "ascii"
    )
)


def map_username_to_mxid_localpart(
    username: Union[str, bytes], case_sensitive: bool = False
) -> str:
    """Map a username onto a string suitable for a MXID

    This follows the algorithm laid out at
    https://matrix.org/docs/spec/appendices.html#mapping-from-other-character-sets.

    Args:
        username: username to be mapped
        case_sensitive: true if TEST and test should be mapped
            onto different mxids

    Returns:
        string suitable for a mxid localpart
    """
    if not isinstance(username, bytes):
        username = username.encode("utf-8")

    # first we sort out upper-case characters
    if case_sensitive:

        def f1(m: Match[bytes]) -> bytes:
            return b"_" + m.group().lower()

        username = UPPER_CASE_PATTERN.sub(f1, username)
    else:
        username = username.lower()

    # then we sort out non-ascii characters by converting to the hex equivalent.
    def f2(m: Match[bytes]) -> bytes:
        return b"=%02x" % (m.group()[0],)

    username = NON_MXID_CHARACTER_PATTERN.sub(f2, username)

    # we also do the =-escaping to mxids starting with an underscore.
    username = re.sub(b"^_", b"=5f", username)

    # we should now only have ascii bytes left, so can decode back to a string.
    return username.decode("ascii")


@attr.s(frozen=True, slots=True, order=False)
class RoomStreamToken:
    """Tokens are positions between events. The token "s1" comes after event 1.

            s0    s1
            |     |
        [0] ▼ [1] ▼ [2]

    Tokens can either be a point in the live event stream or a cursor going
    through historic events.

    When traversing the live event stream, events are ordered by
    `stream_ordering` (when they arrived at the homeserver).

    When traversing historic events, events are first ordered by their `depth`
    (`topological_ordering` in the event graph) and tie-broken by
    `stream_ordering` (when the event arrived at the homeserver).

    If you're looking for more info about what a token with all of the
    underscores means, ex.
    `s2633508_17_338_6732159_1082514_541479_274711_265584_1`, see the docstring
    for `StreamToken` below.

    ---

    Live tokens start with an "s" followed by the `stream_ordering` of the event
    that comes before the position of the token. Said another way:
    `stream_ordering` uniquely identifies a persisted event. The live token
    means "the position just after the event identified by `stream_ordering`".
    An example token is:

        s2633508

    ---

    Historic tokens start with a "t" followed by the `depth`
    (`topological_ordering` in the event graph) of the event that comes before
    the position of the token, followed by "-", followed by the
    `stream_ordering` of the event that comes before the position of the token.
    An example token is:

        t426-2633508

    ---

    There is also a third mode for live tokens where the token starts with "m",
    which is sometimes used when using sharded event persisters. In this case
    the events stream is considered to be a set of streams (one for each writer)
    and the token encodes the vector clock of positions of each writer in their
    respective streams.

    The format of the token in such case is an initial integer min position,
    followed by the mapping of instance ID to position separated by '.' and '~':

        m{min_pos}~{writer1}.{pos1}~{writer2}.{pos2}. ...

    The `min_pos` corresponds to the minimum position all writers have persisted
    up to, and then only writers that are ahead of that position need to be
    encoded. An example token is:

        m56~2.58~3.59

    Which corresponds to a set of three (or more writers) where instances 2 and
    3 (these are instance IDs that can be looked up in the DB to fetch the more
    commonly used instance names) are at positions 58 and 59 respectively, and
    all other instances are at position 56.

    Note: The `RoomStreamToken` cannot have both a topological part and an
    instance map.

    ---

    For caching purposes, `RoomStreamToken`s and by extension, all their
    attributes, must be hashable.
    """

    topological: Optional[int] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(int)),
    )
    stream: int = attr.ib(validator=attr.validators.instance_of(int))

    instance_map: "frozendict[str, int]" = attr.ib(
        factory=frozendict,
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(str),
            value_validator=attr.validators.instance_of(int),
            mapping_validator=attr.validators.instance_of(frozendict),
        ),
    )

    def __attrs_post_init__(self) -> None:
        """Validates that both `topological` and `instance_map` aren't set."""

        if self.instance_map and self.topological:
            raise ValueError(
                "Cannot set both 'topological' and 'instance_map' on 'RoomStreamToken'."
            )

    @classmethod
    async def parse(cls, store: "PurgeEventsStore", string: str) -> "RoomStreamToken":
        try:
            if string[0] == "s":
                return cls(topological=None, stream=int(string[1:]))
            if string[0] == "t":
                parts = string[1:].split("-", 1)
                return cls(topological=int(parts[0]), stream=int(parts[1]))
            if string[0] == "m":
                parts = string[1:].split("~")
                stream = int(parts[0])

                instance_map = {}
                for part in parts[1:]:
                    key, value = part.split(".")
                    instance_id = int(key)
                    pos = int(value)

                    instance_name = await store.get_name_from_instance_id(instance_id)  # type: ignore[attr-defined]
                    instance_map[instance_name] = pos

                return cls(
                    topological=None,
                    stream=stream,
                    instance_map=frozendict(instance_map),
                )
        except CancelledError:
            raise
        except Exception:
            pass
        raise SynapseError(400, "Invalid room stream token %r" % (string,))

    @classmethod
    def parse_stream_token(cls, string: str) -> "RoomStreamToken":
        try:
            if string[0] == "s":
                return cls(topological=None, stream=int(string[1:]))
        except Exception:
            pass
        raise SynapseError(400, "Invalid room stream token %r" % (string,))

    def copy_and_advance(self, other: "RoomStreamToken") -> "RoomStreamToken":
        """Return a new token such that if an event is after both this token and
        the other token, then its after the returned token too.
        """

        if self.topological or other.topological:
            raise Exception("Can't advance topological tokens")

        max_stream = max(self.stream, other.stream)

        instance_map = {
            instance: max(
                self.instance_map.get(instance, self.stream),
                other.instance_map.get(instance, other.stream),
            )
            for instance in set(self.instance_map).union(other.instance_map)
        }

        return RoomStreamToken(None, max_stream, frozendict(instance_map))

    def as_historical_tuple(self) -> Tuple[int, int]:
        """Returns a tuple of `(topological, stream)` for historical tokens.

        Raises if not an historical token (i.e. doesn't have a topological part).
        """
        if self.topological is None:
            raise Exception(
                "Cannot call `RoomStreamToken.as_historical_tuple` on live token"
            )

        return self.topological, self.stream

    def get_stream_pos_for_instance(self, instance_name: str) -> int:
        """Get the stream position that the given writer was at at this token.

        This only makes sense for "live" tokens that may have a vector clock
        component, and so asserts that this is a "live" token.
        """
        assert self.topological is None

        # If we don't have an entry for the instance we can assume that it was
        # at `self.stream`.
        return self.instance_map.get(instance_name, self.stream)

    def get_max_stream_pos(self) -> int:
        """Get the maximum stream position referenced in this token.

        The corresponding "min" position is, by definition just `self.stream`.

        This is used to handle tokens that have non-empty `instance_map`, and so
        reference stream positions after the `self.stream` position.
        """
        return max(self.instance_map.values(), default=self.stream)

    async def to_string(self, store: "DataStore") -> str:
        if self.topological is not None:
            return "t%d-%d" % (self.topological, self.stream)
        elif self.instance_map:
            entries = []
            for name, pos in self.instance_map.items():
                instance_id = await store.get_id_for_instance(name)
                entries.append(f"{instance_id}.{pos}")

            encoded_map = "~".join(entries)
            return f"m{self.stream}~{encoded_map}"
        else:
            return "s%d" % (self.stream,)


class StreamKeyType:
    """Known stream types.

    A stream is a list of entities ordered by an incrementing "stream token".
    """

    ROOM: Final = "room_key"
    PRESENCE: Final = "presence_key"
    TYPING: Final = "typing_key"
    RECEIPT: Final = "receipt_key"
    ACCOUNT_DATA: Final = "account_data_key"
    PUSH_RULES: Final = "push_rules_key"
    TO_DEVICE: Final = "to_device_key"
    DEVICE_LIST: Final = "device_list_key"


@attr.s(slots=True, frozen=True, auto_attribs=True)
class StreamToken:
    """A collection of keys joined together by underscores in the following
    order and which represent the position in their respective streams.

    ex. `s2633508_17_338_6732159_1082514_541479_274711_265584_1`
        1. `room_key`: `s2633508` which is a `RoomStreamToken`
           - `RoomStreamToken`'s can also look like `t426-2633508` or `m56~2.58~3.59`
           - See the docstring for `RoomStreamToken` for more details.
        2. `presence_key`: `17`
        3. `typing_key`: `338`
        4. `receipt_key`: `6732159`
        5. `account_data_key`: `1082514`
        6. `push_rules_key`: `541479`
        7. `to_device_key`: `274711`
        8. `device_list_key`: `265584`
        9. `groups_key`: `1` (note that this key is now unused)

    You can see how many of these keys correspond to the various
    fields in a "/sync" response:
    ```json
    {
        "next_batch": "s12_4_0_1_1_1_1_4_1",
        "presence": {
            "events": []
        },
        "device_lists": {
            "changed": []
        },
        "rooms": {
            "join": {
                "!QrZlfIDQLNLdZHqTnt:hs1": {
                    "timeline": {
                        "events": [],
                        "prev_batch": "s10_4_0_1_1_1_1_4_1",
                        "limited": false
                    },
                    "state": {
                        "events": []
                    },
                    "account_data": {
                        "events": []
                    },
                    "ephemeral": {
                        "events": []
                    }
                }
            }
        }
    }
    ```

    ---

    For caching purposes, `StreamToken`s and by extension, all their attributes,
    must be hashable.
    """

    room_key: RoomStreamToken = attr.ib(
        validator=attr.validators.instance_of(RoomStreamToken)
    )
    presence_key: int
    typing_key: int
    receipt_key: int
    account_data_key: int
    push_rules_key: int
    to_device_key: int
    device_list_key: int
    # Note that the groups key is no longer used and may have bogus values.
    groups_key: int

    _SEPARATOR = "_"
    START: ClassVar["StreamToken"]

    @classmethod
    @cancellable
    async def from_string(cls, store: "DataStore", string: str) -> "StreamToken":
        """
        Creates a RoomStreamToken from its textual representation.
        """
        try:
            keys = string.split(cls._SEPARATOR)
            while len(keys) < len(attr.fields(cls)):
                # i.e. old token from before receipt_key
                keys.append("0")
            return cls(
                await RoomStreamToken.parse(store, keys[0]), *(int(k) for k in keys[1:])
            )
        except CancelledError:
            raise
        except Exception:
            raise SynapseError(400, "Invalid stream token")

    async def to_string(self, store: "DataStore") -> str:
        return self._SEPARATOR.join(
            [
                await self.room_key.to_string(store),
                str(self.presence_key),
                str(self.typing_key),
                str(self.receipt_key),
                str(self.account_data_key),
                str(self.push_rules_key),
                str(self.to_device_key),
                str(self.device_list_key),
                # Note that the groups key is no longer used, but it is still
                # serialized so that there will not be confusion in the future
                # if additional tokens are added.
                str(self.groups_key),
            ]
        )

    @property
    def room_stream_id(self) -> int:
        return self.room_key.stream

    def copy_and_advance(self, key: str, new_value: Any) -> "StreamToken":
        """Advance the given key in the token to a new value if and only if the
        new value is after the old value.

        :raises TypeError: if `key` is not the one of the keys tracked by a StreamToken.
        """
        if key == StreamKeyType.ROOM:
            new_token = self.copy_and_replace(
                StreamKeyType.ROOM, self.room_key.copy_and_advance(new_value)
            )
            return new_token

        new_token = self.copy_and_replace(key, new_value)
        new_id = int(getattr(new_token, key))
        old_id = int(getattr(self, key))

        if old_id < new_id:
            return new_token
        else:
            return self

    def copy_and_replace(self, key: str, new_value: Any) -> "StreamToken":
        return attr.evolve(self, **{key: new_value})


StreamToken.START = StreamToken(RoomStreamToken(None, 0), 0, 0, 0, 0, 0, 0, 0, 0)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class PersistedEventPosition:
    """Position of a newly persisted event with instance that persisted it.

    This can be used to test whether the event is persisted before or after a
    RoomStreamToken.
    """

    instance_name: str
    stream: int

    def persisted_after(self, token: RoomStreamToken) -> bool:
        return token.get_stream_pos_for_instance(self.instance_name) < self.stream

    def to_room_stream_token(self) -> RoomStreamToken:
        """Converts the position to a room stream token such that events
        persisted in the same room after this position will be after the
        returned `RoomStreamToken`.

        Note: no guarantees are made about ordering w.r.t. events in other
        rooms.
        """
        # Doing the naive thing satisfies the desired properties described in
        # the docstring.
        return RoomStreamToken(None, self.stream)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ThirdPartyInstanceID:
    appservice_id: Optional[str]
    network_id: Optional[str]

    # Deny iteration because it will bite you if you try to create a singleton
    # set by:
    #    users = set(user)
    def __iter__(self) -> NoReturn:
        raise ValueError("Attempted to iterate a %s" % (type(self).__name__,))

    # Because this class is a frozen class, it is deeply immutable.
    def __copy__(self) -> "ThirdPartyInstanceID":
        return self

    def __deepcopy__(self, memo: Dict[str, object]) -> "ThirdPartyInstanceID":
        return self

    @classmethod
    def from_string(cls, s: str) -> "ThirdPartyInstanceID":
        bits = s.split("|", 2)
        if len(bits) != 2:
            raise SynapseError(400, "Invalid ID %r" % (s,))

        return cls(appservice_id=bits[0], network_id=bits[1])

    def to_string(self) -> str:
        return "%s|%s" % (self.appservice_id, self.network_id)

    __str__ = to_string


@attr.s(slots=True, frozen=True, auto_attribs=True)
class ReadReceipt:
    """Information about a read-receipt"""

    room_id: str
    receipt_type: str
    user_id: str
    event_ids: List[str]
    thread_id: Optional[str]
    data: JsonDict


@attr.s(slots=True, frozen=True, auto_attribs=True)
class DeviceListUpdates:
    """
    An object containing a diff of information regarding other users' device lists, intended for
    a recipient to carry out device list tracking.

    Attributes:
        changed: A set of users whose device lists have changed recently.
        left: A set of users who the recipient no longer needs to track the device lists of.
            Typically when those users no longer share any end-to-end encryption enabled rooms.
    """

    # We need to use a factory here, otherwise `set` is not evaluated at
    # object instantiation, but instead at class definition instantiation.
    # The latter happening only once, thus always giving you the same sets
    # across multiple DeviceListUpdates instances.
    # Also see: don't define mutable default arguments.
    changed: Set[str] = attr.ib(factory=set)
    left: Set[str] = attr.ib(factory=set)

    def __bool__(self) -> bool:
        return bool(self.changed or self.left)


def get_verify_key_from_cross_signing_key(
    key_info: Mapping[str, Any]
) -> Tuple[str, VerifyKey]:
    """Get the key ID and signedjson verify key from a cross-signing key dict

    Args:
        key_info: a cross-signing key dict, which must have a "keys"
            property that has exactly one item in it

    Returns:
        the key ID and verify key for the cross-signing key
    """
    # make sure that a `keys` field is provided
    if "keys" not in key_info:
        raise ValueError("Invalid key")
    keys = key_info["keys"]
    # and that it contains exactly one key
    if len(keys) == 1:
        key_id, key_data = next(iter(keys.items()))
        return key_id, decode_verify_key_bytes(key_id, decode_base64(key_data))
    else:
        raise ValueError("Invalid key")


@attr.s(auto_attribs=True, frozen=True, slots=True)
class UserInfo:
    """Holds information about a user. Result of get_userinfo_by_id.

    Attributes:
        user_id:  ID of the user.
        appservice_id:  Application service ID that created this user.
        consent_server_notice_sent:  Version of policy documents the user has been sent.
        consent_version:  Version of policy documents the user has consented to.
        creation_ts:  Creation timestamp of the user.
        is_admin:  True if the user is an admin.
        is_deactivated:  True if the user has been deactivated.
        is_guest:  True if the user is a guest user.
        is_shadow_banned:  True if the user has been shadow-banned.
        user_type:  User type (None for normal user, 'support' and 'bot' other options).
    """

    user_id: UserID
    appservice_id: Optional[int]
    consent_server_notice_sent: Optional[str]
    consent_version: Optional[str]
    user_type: Optional[str]
    creation_ts: int
    is_admin: bool
    is_deactivated: bool
    is_guest: bool
    is_shadow_banned: bool


class UserProfile(TypedDict):
    user_id: str
    display_name: Optional[str]
    avatar_url: Optional[str]


@attr.s(auto_attribs=True, frozen=True, slots=True)
class RetentionPolicy:
    min_lifetime: Optional[int] = None
    max_lifetime: Optional[int] = None
