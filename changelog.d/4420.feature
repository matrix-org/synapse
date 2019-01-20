New listener resource for the federation API "openid/userinfo" endpoint

Integration managers use the OpenID userinfo endpoint in the federation API to verify that user
OpenID access tokens are valid. If the federation resource is disabled, integration managers will not be able
to verify the access token, causing a broken experience for users. The OpenID userinfo endpoint has now been split
to a separate `openid` resource, which is enabled by default in newly generated configuration. It is also enabled
automatically if the federation resource is enabled.

If your homeserver runs federation enabled, this change does not require any actions.

If you run a homeserver with federation disabled, we recommend adding the `openid` resource to your homeserver
configuration in the `type: http` listener `resources` list to allow your users access to
integration manager features.
