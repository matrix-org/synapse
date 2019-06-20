# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from .api import ApiConfig
from .appservice import AppServiceConfig
from .captcha import CaptchaConfig
from .cas import CasConfig
from .consent_config import ConsentConfig
from .database import DatabaseConfig
from .emailconfig import EmailConfig
from .groups import GroupsConfig
from .jwt_config import JWTConfig
from .key import KeyConfig
from .logger import LoggingConfig
from .metrics import MetricsConfig
from .password import PasswordConfig
from .password_auth_providers import PasswordAuthProviderConfig
from .push import PushConfig
from .ratelimiting import RatelimitConfig
from .registration import RegistrationConfig
from .repository import ContentRepositoryConfig
from .room_directory import RoomDirectoryConfig
from .saml2_config import SAML2Config
from .server import ServerConfig
from .server_notices_config import ServerNoticesConfig
from .spam_checker import SpamCheckerConfig
from .stats import StatsConfig
from .third_party_event_rules import ThirdPartyRulesConfig
from .tls import TlsConfig
from .user_directory import UserDirectoryConfig
from .voip import VoipConfig
from .workers import WorkerConfig


class HomeServerConfig(
    ServerConfig,
    TlsConfig,
    DatabaseConfig,
    LoggingConfig,
    RatelimitConfig,
    ContentRepositoryConfig,
    CaptchaConfig,
    VoipConfig,
    RegistrationConfig,
    MetricsConfig,
    ApiConfig,
    AppServiceConfig,
    KeyConfig,
    SAML2Config,
    CasConfig,
    JWTConfig,
    PasswordConfig,
    EmailConfig,
    WorkerConfig,
    PasswordAuthProviderConfig,
    PushConfig,
    SpamCheckerConfig,
    GroupsConfig,
    UserDirectoryConfig,
    ConsentConfig,
    StatsConfig,
    ServerNoticesConfig,
    RoomDirectoryConfig,
    ThirdPartyRulesConfig,
):
    pass
