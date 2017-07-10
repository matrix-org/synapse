# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

from twisted.internet import defer

from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.types import GroupID

from ._base import client_v2_patterns

import logging

logger = logging.getLogger(__name__)


class GroupServlet(RestServlet):
    PATTERNS = client_v2_patterns("/groups/(?P<group_id>[^/]*)/profile$")

    def __init__(self, hs):
        super(GroupServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        group_description = yield self.groups_handler.get_group_profile(group_id, user_id)

        defer.returnValue((200, group_description))


class GroupSummaryServlet(RestServlet):
    PATTERNS = client_v2_patterns("/groups/(?P<group_id>[^/]*)/summary$")

    def __init__(self, hs):
        super(GroupSummaryServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        get_group_summary = yield self.groups_handler.get_group_summary(group_id, user_id)

        defer.returnValue((200, get_group_summary))


class GroupSummaryRoomsServlet(RestServlet):
    PATTERNS = client_v2_patterns("/groups/(?P<group_id>[^/]*)/summary/rooms$")

    def __init__(self, hs):
        super(GroupSummaryServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        get_group_summary = yield self.groups_handler.get_group_summary(group_id, user_id)

        defer.returnValue((200, get_group_summary))


class GroupSummaryRoomsDefaultCatServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/summary/rooms/(?P<room_id>[^/]*)$"
    )

    def __init__(self, hs):
        super(GroupSummaryRoomsDefaultCatServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, room_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        resp = yield self.groups_handler.update_group_summary_room(
            group_id, user_id,
            room_id=room_id,
            category_id=None,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, request, group_id, room_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        resp = yield self.groups_handler.delete_group_summary_room(
            group_id, user_id,
            room_id=room_id,
            category_id=None,
        )

        defer.returnValue((200, resp))


class GroupSummaryRoomsCatServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/summary"
        "/categories/(?P<category_id>[^/]+)/rooms/(?P<room_id>[^/]+)$"
    )

    def __init__(self, hs):
        super(GroupSummaryRoomsCatServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, category_id, room_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        resp = yield self.groups_handler.update_group_summary_room(
            group_id, user_id,
            room_id=room_id,
            category_id=category_id,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, request, group_id, category_id, room_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        resp = yield self.groups_handler.delete_group_summary_room(
            group_id, user_id,
            room_id=room_id,
            category_id=category_id,
        )

        defer.returnValue((200, resp))


class GroupCategoryServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/categories/(?P<category_id>[^/]+)$"
    )

    def __init__(self, hs):
        super(GroupCategoryServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id, category_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        category = yield self.groups_handler.get_group_category(
            group_id, user_id,
            category_id=category_id,
        )

        defer.returnValue((200, category))

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, category_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        resp = yield self.groups_handler.update_group_category(
            group_id, user_id,
            category_id=category_id,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, request, group_id, category_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        resp = yield self.groups_handler.delete_group_category(
            group_id, user_id,
            category_id=category_id,
        )

        defer.returnValue((200, resp))


class GroupCategoriesServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/categories/$"
    )

    def __init__(self, hs):
        super(GroupCategoriesServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        category = yield self.groups_handler.get_group_categories(
            group_id, user_id,
        )

        defer.returnValue((200, category))


class GroupRoleServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/roles/(?P<role_id>[^/]+)$"
    )

    def __init__(self, hs):
        super(GroupRoleServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id, role_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        category = yield self.groups_handler.get_group_role(
            group_id, user_id,
            role_id=role_id,
        )

        defer.returnValue((200, category))

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, role_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        resp = yield self.groups_handler.update_group_role(
            group_id, user_id,
            role_id=role_id,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, request, group_id, role_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        resp = yield self.groups_handler.delete_group_role(
            group_id, user_id,
            role_id=role_id,
        )

        defer.returnValue((200, resp))


class GroupRolesServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/roles/$"
    )

    def __init__(self, hs):
        super(GroupRolesServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        category = yield self.groups_handler.get_group_roles(
            group_id, user_id,
        )

        defer.returnValue((200, category))


class GroupSummaryUsersDefaultRoleServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/summary/users/(?P<user_id>[^/]*)$"
    )

    def __init__(self, hs):
        super(GroupSummaryUsersDefaultRoleServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, user_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        resp = yield self.groups_handler.update_group_summary_user(
            group_id, requester_user_id,
            user_id=user_id,
            role_id=None,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, request, group_id, user_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        resp = yield self.groups_handler.delete_group_summary_user(
            group_id, requester_user_id,
            user_id=user_id,
            role_id=None,
        )

        defer.returnValue((200, resp))


class GroupSummaryUsersRoleServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/summary"
        "/roles/(?P<role_id>[^/]+)/users/(?P<user_id>[^/]+)$"
    )

    def __init__(self, hs):
        super(GroupSummaryUsersRoleServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, role_id, user_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        resp = yield self.groups_handler.update_group_summary_user(
            group_id, requester_user_id,
            user_id=user_id,
            role_id=role_id,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, request, group_id, role_id, user_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        resp = yield self.groups_handler.delete_group_summary_user(
            group_id, requester_user_id,
            user_id=user_id,
            role_id=role_id,
        )

        defer.returnValue((200, resp))


class GroupRoomServlet(RestServlet):
    PATTERNS = client_v2_patterns("/groups/(?P<group_id>[^/]*)/rooms$")

    def __init__(self, hs):
        super(GroupRoomServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        result = yield self.groups_handler.get_rooms_in_group(group_id, user_id)

        defer.returnValue((200, result))


class GroupUsersServlet(RestServlet):
    PATTERNS = client_v2_patterns("/groups/(?P<group_id>[^/]*)/users$")

    def __init__(self, hs):
        super(GroupUsersServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        result = yield self.groups_handler.get_users_in_group(group_id, user_id)

        defer.returnValue((200, result))


class GroupCreateServlet(RestServlet):
    PATTERNS = client_v2_patterns("/create_group$")

    def __init__(self, hs):
        super(GroupCreateServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()
        self.server_name = hs.hostname

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        # TODO: Create group on remote server
        content = parse_json_object_from_request(request)
        localpart = content.pop("localpart")
        group_id = GroupID.create(localpart, self.server_name).to_string()

        result = yield self.groups_handler.create_group(group_id, user_id, content)

        defer.returnValue((200, result))


class GroupAdminRoomsServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/rooms/(?P<room_id>[^/]*)$"
    )

    def __init__(self, hs):
        super(GroupAdminRoomsServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, room_id):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        result = yield self.groups_handler.add_room(group_id, user_id, room_id, content)

        defer.returnValue((200, result))


class GroupAdminUsersInviteServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/users/invite/(?P<user_id>[^/]*)$"
    )

    def __init__(self, hs):
        super(GroupAdminUsersInviteServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()
        self.store = hs.get_datastore()
        self.is_mine_id = hs.is_mine_id

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, user_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        config = content.get("config", {})
        result = yield self.groups_handler.invite(
            group_id, user_id, requester_user_id, config,
        )

        defer.returnValue((200, result))


class GroupAdminUsersKickServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/users/remove/(?P<user_id>[^/]*)$"
    )

    def __init__(self, hs):
        super(GroupAdminUsersKickServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id, user_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        result = yield self.groups_handler.remove_user_from_group(
            group_id, user_id, requester_user_id, content,
        )

        defer.returnValue((200, result))


class GroupSelfLeaveServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/self/leave$"
    )

    def __init__(self, hs):
        super(GroupSelfLeaveServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        result = yield self.groups_handler.remove_user_from_group(
            group_id, requester_user_id, requester_user_id, content,
        )

        defer.returnValue((200, result))


class GroupSelfJoinServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/self/join$"
    )

    def __init__(self, hs):
        super(GroupSelfJoinServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        result = yield self.groups_handler.join_group(
            group_id, requester_user_id, content,
        )

        defer.returnValue((200, result))


class GroupSelfAcceptInviteServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/groups/(?P<group_id>[^/]*)/self/accept_invite$"
    )

    def __init__(self, hs):
        super(GroupSelfAcceptInviteServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        result = yield self.groups_handler.accept_invite(
            group_id, requester_user_id, content,
        )

        defer.returnValue((200, result))


class GroupsForUserServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/joined_groups$"
    )

    def __init__(self, hs):
        super(GroupsForUserServlet, self).__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        result = yield self.groups_handler.get_joined_groups(user_id)

        defer.returnValue((200, result))


def register_servlets(hs, http_server):
    GroupServlet(hs).register(http_server)
    GroupSummaryServlet(hs).register(http_server)
    GroupUsersServlet(hs).register(http_server)
    GroupRoomServlet(hs).register(http_server)
    GroupCreateServlet(hs).register(http_server)
    GroupAdminRoomsServlet(hs).register(http_server)
    GroupAdminUsersInviteServlet(hs).register(http_server)
    GroupAdminUsersKickServlet(hs).register(http_server)
    GroupSelfLeaveServlet(hs).register(http_server)
    GroupSelfJoinServlet(hs).register(http_server)
    GroupSelfAcceptInviteServlet(hs).register(http_server)
    GroupsForUserServlet(hs).register(http_server)
    GroupSummaryRoomsDefaultCatServlet(hs).register(http_server)
    GroupCategoryServlet(hs).register(http_server)
    GroupCategoriesServlet(hs).register(http_server)
    GroupSummaryRoomsCatServlet(hs).register(http_server)
    GroupRoleServlet(hs).register(http_server)
    GroupRolesServlet(hs).register(http_server)
    GroupSummaryUsersDefaultRoleServlet(hs).register(http_server)
    GroupSummaryUsersRoleServlet(hs).register(http_server)
