# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from .tls import TlsConfig
from .server import ServerConfig
from .logger import LoggingConfig
from .database import DatabaseConfig
from .ratelimiting import RatelimitConfig
from .repository import ContentRepositoryConfig
from .captcha import CaptchaConfig
from .voip import VoipConfig
from .registration import RegistrationConfig
from .metrics import MetricsConfig
from .api import ApiConfig
from .appservice import AppServiceConfig
from .key import KeyConfig
from .saml2 import SAML2Config
from .cas import CasConfig
from .password import PasswordConfig
from .jwt import JWTConfig
from .password_auth_providers import PasswordAuthProviderConfig
from .emailconfig import EmailConfig
from .workers import WorkerConfig


class HomeServerConfig(TlsConfig, ServerConfig, DatabaseConfig, LoggingConfig,
                       RatelimitConfig, ContentRepositoryConfig, CaptchaConfig,
                       VoipConfig, RegistrationConfig, MetricsConfig, ApiConfig,
                       AppServiceConfig, KeyConfig, SAML2Config, CasConfig,
                       JWTConfig, PasswordConfig, EmailConfig,
                       WorkerConfig, PasswordAuthProviderConfig,):
    pass


if __name__ == '__main__':
    import sys
    sys.stdout.write(
        HomeServerConfig().generate_config(sys.argv[1], sys.argv[2])[0]
    )
