from synapse.config import api
from synapse.config import appservice
from synapse.config import captcha
from synapse.config import cas
from synapse.config import consent_config
from synapse.config import database
from synapse.config import emailconfig
from synapse.config import groups
from synapse.config import jwt_config
from synapse.config import key
from synapse.config import logger
from synapse.config import metrics
from synapse.config import password
from synapse.config import password_auth_providers
from synapse.config import push
from synapse.config import ratelimiting
from synapse.config import registration
from synapse.config import repository
from synapse.config import room_directory
from synapse.config import saml2_config
from synapse.config import server
from synapse.config import server_notices_config
from synapse.config import spam_checker
from synapse.config import stats
from synapse.config import third_party_event_rules
from synapse.config import tls
from synapse.config import tracer
from synapse.config import user_directory
from synapse.config import voip
from synapse.config import workers

class RootConfig(object):

    server: server.ServerConfig
    tls: tls.TlsConfig
    database: database.DatabaseConfig
    logging: logger.LoggingConfig
    ratelimit: ratelimiting.RatelimitConfig
    contentrepository: repository.ContentRepositoryConfig
    captcha: captcha.CaptchaConfig
    voip: voip.VoipConfig
    registration: registration.RegistrationConfig
    metrics: metrics.MetricsConfig
    api: api.ApiConfig
    appservice: appservice.AppServiceConfig
    key: key.KeyConfig
    saml2: saml2_config.SAML2Config
    cas: cas.CasConfig
    jwt: jwt_config.JWTConfig
    password: password.PasswordConfig
    email: emailconfig.EmailConfig
    worker: workers.WorkerConfig
    passwordauthprovider: password_auth_providers.PasswordAuthProviderConfig
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
