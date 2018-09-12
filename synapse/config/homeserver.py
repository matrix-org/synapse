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
from .saml2 import SAML2Config
from .server import ServerConfig
from .server_notices_config import ServerNoticesConfig
from .spam_checker import SpamCheckerConfig
from .tls import TlsConfig
from .user_directory import UserDirectoryConfig
from .voip import VoipConfig
from .workers import WorkerConfig


class HomeServerConfig(TlsConfig, ServerConfig, DatabaseConfig, LoggingConfig,
                       RatelimitConfig, ContentRepositoryConfig, CaptchaConfig,
                       VoipConfig, RegistrationConfig, MetricsConfig, ApiConfig,
                       AppServiceConfig, KeyConfig, SAML2Config, CasConfig,
                       JWTConfig, PasswordConfig, EmailConfig,
                       WorkerConfig, PasswordAuthProviderConfig, PushConfig,
                       SpamCheckerConfig, GroupsConfig, UserDirectoryConfig,
                       ConsentConfig,
                       ServerNoticesConfig,
                       ):
    pass


if __name__ == '__main__':
    import sys
    sys.stdout.write(
        HomeServerConfig().generate_config(sys.argv[1], sys.argv[2], True)[0]
    )
