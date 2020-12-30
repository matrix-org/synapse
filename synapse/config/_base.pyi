from typing import Any, Iterable, List, Optional

from synapse.config import (
    api,
    appservice,
    auth,
    captcha,
    cas,
    consent_config,
    database,
    emailconfig,
    groups,
    jwt_config,
    key,
    logger,
    metrics,
    oidc_config,
    password_auth_providers,
    push,
    ratelimiting,
    registration,
    repository,
    room_directory,
    saml2_config,
    server,
    server_notices_config,
    spam_checker,
    sso,
    stats,
    third_party_event_rules,
    tls,
    tracer,
    user_directory,
    voip,
    workers,
)

class ConfigError(Exception):
    def __init__(self, msg: str, path: Optional[Iterable[str]] = None):
        self.msg = msg
        self.path = path

MISSING_REPORT_STATS_CONFIG_INSTRUCTIONS: str
MISSING_REPORT_STATS_SPIEL: str
MISSING_SERVER_NAME: str

def path_exists(file_path: str): ...

class RootConfig:
    server: server.ServerConfig
    tls: tls.TlsConfig
    database: database.DatabaseConfig
    logging: logger.LoggingConfig
    ratelimit: ratelimiting.RatelimitConfig
    media: repository.ContentRepositoryConfig
    captcha: captcha.CaptchaConfig
    voip: voip.VoipConfig
    registration: registration.RegistrationConfig
    metrics: metrics.MetricsConfig
    api: api.ApiConfig
    appservice: appservice.AppServiceConfig
    key: key.KeyConfig
    saml2: saml2_config.SAML2Config
    cas: cas.CasConfig
    sso: sso.SSOConfig
    oidc: oidc_config.OIDCConfig
    jwt: jwt_config.JWTConfig
    auth: auth.AuthConfig
    email: emailconfig.EmailConfig
    worker: workers.WorkerConfig
    authproviders: password_auth_providers.PasswordAuthProviderConfig
    push: push.PushConfig
    spamchecker: spam_checker.SpamCheckerConfig
    groups: groups.GroupsConfig
    userdirectory: user_directory.UserDirectoryConfig
    consent: consent_config.ConsentConfig
    stats: stats.StatsConfig
    servernotices: server_notices_config.ServerNoticesConfig
    roomdirectory: room_directory.RoomDirectoryConfig
    thirdpartyrules: third_party_event_rules.ThirdPartyRulesConfig
    tracer: tracer.TracerConfig

    config_classes: List = ...
    def __init__(self) -> None: ...
    def invoke_all(self, func_name: str, *args: Any, **kwargs: Any): ...
    @classmethod
    def invoke_all_static(cls, func_name: str, *args: Any, **kwargs: Any) -> None: ...
    def __getattr__(self, item: str): ...
    def parse_config_dict(
        self,
        config_dict: Any,
        config_dir_path: Optional[Any] = ...,
        data_dir_path: Optional[Any] = ...,
    ) -> None: ...
    read_config: Any = ...
    def generate_config(
        self,
        config_dir_path: str,
        data_dir_path: str,
        server_name: str,
        generate_secrets: bool = ...,
        report_stats: Optional[str] = ...,
        open_private_ports: bool = ...,
        listeners: Optional[Any] = ...,
        database_conf: Optional[Any] = ...,
        tls_certificate_path: Optional[str] = ...,
        tls_private_key_path: Optional[str] = ...,
        acme_domain: Optional[str] = ...,
    ): ...
    @classmethod
    def load_or_generate_config(cls, description: Any, argv: Any): ...
    @classmethod
    def load_config(cls, description: Any, argv: Any): ...
    @classmethod
    def add_arguments_to_parser(cls, config_parser: Any) -> None: ...
    @classmethod
    def load_config_with_parser(cls, parser: Any, argv: Any): ...
    def generate_missing_files(
        self, config_dict: dict, config_dir_path: str
    ) -> None: ...

class Config:
    root: RootConfig
    def __init__(self, root_config: Optional[RootConfig] = ...) -> None: ...
    def __getattr__(self, item: str, from_root: bool = ...): ...
    @staticmethod
    def parse_size(value: Any): ...
    @staticmethod
    def parse_duration(value: Any): ...
    @staticmethod
    def abspath(file_path: Optional[str]): ...
    @classmethod
    def path_exists(cls, file_path: str): ...
    @classmethod
    def check_file(cls, file_path: str, config_name: str): ...
    @classmethod
    def ensure_directory(cls, dir_path: str): ...
    @classmethod
    def read_file(cls, file_path: str, config_name: str): ...

def read_config_files(config_files: List[str]): ...
def find_config_files(search_paths: List[str]): ...

class ShardedWorkerHandlingConfig:
    instances: List[str]
    def __init__(self, instances: List[str]) -> None: ...
    def should_handle(self, instance_name: str, key: str) -> bool: ...
    def get_instance(self, key: str) -> str: ...
