from synapse.config import (
    api,
    appservice,
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
    password,
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
    stats,
    third_party_event_rules,
    tls,
    tracer,
    user_directory,
    voip,
    workers,
)

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
