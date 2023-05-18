# Configuring Synapse to authenticate against an OpenID Connect provider

Synapse can be configured to use an OpenID Connect Provider (OP) for
authentication, instead of its own local password database.

Any OP should work with Synapse, as long as it supports the authorization code
flow. There are a few options for that:

 - start a local OP. Synapse has been tested with [Hydra][hydra] and
   [Dex][dex-idp].  Note that for an OP to work, it should be served under a
   secure (HTTPS) origin.  A certificate signed with a self-signed, locally
   trusted CA should work. In that case, start Synapse with a `SSL_CERT_FILE`
   environment variable set to the path of the CA.

 - set up a SaaS OP, like [Google][google-idp], [Auth0][auth0] or
   [Okta][okta]. Synapse has been tested with Auth0 and Google.

It may also be possible to use other OAuth2 providers which provide the
[authorization code grant type](https://tools.ietf.org/html/rfc6749#section-4.1),
such as [Github][github-idp].

[google-idp]: https://developers.google.com/identity/protocols/oauth2/openid-connect
[auth0]: https://auth0.com/
[authentik]: https://goauthentik.io/
[lemonldap]: https://lemonldap-ng.org/
[okta]: https://www.okta.com/
[dex-idp]: https://github.com/dexidp/dex
[keycloak-idp]: https://www.keycloak.org/docs/latest/server_admin/#sso-protocols
[hydra]: https://www.ory.sh/docs/hydra/
[github-idp]: https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps

## Preparing Synapse

The OpenID integration in Synapse uses the
[`authlib`](https://pypi.org/project/Authlib/) library, which must be installed
as follows:

 * The relevant libraries are included in the Docker images and Debian packages
   provided by `matrix.org` so no further action is needed.

 * If you installed Synapse into a virtualenv, run `/path/to/env/bin/pip
   install matrix-synapse[oidc]` to install the necessary dependencies.

 * For other installation mechanisms, see the documentation provided by the
   maintainer.

To enable the OpenID integration, you should then add a section to the `oidc_providers`
setting in your configuration file.
See the [configuration manual](usage/configuration/config_documentation.md#oidc_providers) for some sample settings, as well as
the text below for example configurations for specific providers.

## OIDC Back-Channel Logout

Synapse supports receiving [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) notifications.

This lets the OpenID Connect Provider notify Synapse when a user logs out, so that Synapse can end that user session.
This feature can be enabled by setting the `backchannel_logout_enabled` property to `true` in the provider configuration, and setting the following URL as destination for Back-Channel Logout notifications in your OpenID Connect Provider: `[synapse public baseurl]/_synapse/client/oidc/backchannel_logout`

## Sample configs

Here are a few configs for providers that should work with Synapse.

### Microsoft Azure Active Directory
Azure AD can act as an OpenID Connect Provider. Register a new application under
*App registrations* in the Azure AD management console. The RedirectURI for your
application should point to your matrix server:
`[synapse public baseurl]/_synapse/client/oidc/callback`

Go to *Certificates & secrets* and register a new client secret. Make note of your
Directory (tenant) ID as it will be used in the Azure links.
Edit your Synapse config file and change the `oidc_config` section:

```yaml
oidc_providers:
  - idp_id: microsoft
    idp_name: Microsoft
    issuer: "https://login.microsoftonline.com/<tenant id>/v2.0"
    client_id: "<client id>"
    client_secret: "<client secret>"
    scopes: ["openid", "profile"]
    authorization_endpoint: "https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/authorize"
    token_endpoint: "https://login.microsoftonline.com/<tenant id>/oauth2/v2.0/token"
    userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo"

    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username.split('@')[0] }}"
        display_name_template: "{{ user.name }}"
```

### Apple

Configuring "Sign in with Apple" (SiWA) requires an Apple Developer account.

You will need to create a new "Services ID" for SiWA, and create and download a
private key with "SiWA" enabled.

As well as the private key file, you will need:
 * Client ID: the "identifier" you gave the "Services ID"
 * Team ID: a 10-character ID associated with your developer account.
 * Key ID: the 10-character identifier for the key.

[Apple's developer documentation](https://help.apple.com/developer-account/?lang=en#/dev77c875b7e)
has more information on setting up SiWA.

The synapse config will look like this:

```yaml
  - idp_id: apple
    idp_name: Apple
    issuer: "https://appleid.apple.com"
    client_id: "your-client-id" # Set to the "identifier" for your "ServicesID"
    client_auth_method: "client_secret_post"
    client_secret_jwt_key:
      key_file: "/path/to/AuthKey_KEYIDCODE.p8"  # point to your key file
      jwt_header:
        alg: ES256
        kid: "KEYIDCODE"   # Set to the 10-char Key ID
      jwt_payload:
        iss: TEAMIDCODE    # Set to the 10-char Team ID
    scopes: ["name", "email", "openid"]
    authorization_endpoint: https://appleid.apple.com/auth/authorize?response_mode=form_post
    user_mapping_provider:
      config:
        email_template: "{{ user.email }}"
```

### Auth0

[Auth0][auth0] is a hosted SaaS IdP solution.

1. Create a regular web application for Synapse
2. Set the Allowed Callback URLs to `[synapse public baseurl]/_synapse/client/oidc/callback`
3. Add a rule with any name to add the `preferred_username` claim. 
(See https://auth0.com/docs/customize/rules/create-rules for more information on how to create rules.)
   
   <details>
    <summary>Code sample</summary>

    ```js
    function addPersistenceAttribute(user, context, callback) {
      user.user_metadata = user.user_metadata || {};
      user.user_metadata.preferred_username = user.user_metadata.preferred_username || user.user_id;
      context.idToken.preferred_username = user.user_metadata.preferred_username;

      auth0.users.updateUserMetadata(user.user_id, user.user_metadata)
        .then(function(){
            callback(null, user, context);
        })
        .catch(function(err){
            callback(err);
        });
    }
    ```
  </details>

Synapse config:

```yaml
oidc_providers:
  - idp_id: auth0
    idp_name: Auth0
    issuer: "https://your-tier.eu.auth0.com/" # TO BE FILLED
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    scopes: ["openid", "profile"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
```

### Authentik

[Authentik][authentik] is an open-source IdP solution.

1. Create a provider in Authentik, with type OAuth2/OpenID.
2. The parameters are:
- Client Type: Confidential
- JWT Algorithm: RS256
- Scopes: OpenID, Email and Profile
- RSA Key: Select any available key
- Redirect URIs: `[synapse public baseurl]/_synapse/client/oidc/callback`
3. Create an application for synapse in Authentik and link it to the provider.
4. Note the slug of your application, Client ID and Client Secret.

Note: RSA keys must be used for signing for Authentik, ECC keys do not work.

Synapse config:
```yaml
oidc_providers:
  - idp_id: authentik
    idp_name: authentik
    discover: true
    issuer: "https://your.authentik.example.org/application/o/your-app-slug/" # TO BE FILLED: domain and slug
    client_id: "your client id" # TO BE FILLED
    client_secret: "your client secret" # TO BE FILLED
    scopes:
      - "openid"
      - "profile"
      - "email"
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.preferred_username|capitalize }}" # TO BE FILLED: If your users have names in Authentik and you want those in Synapse, this should be replaced with user.name|capitalize.
```

### Dex

[Dex][dex-idp] is a simple, open-source OpenID Connect Provider.
Although it is designed to help building a full-blown provider with an
external database, it can be configured with static passwords in a config file.

Follow the [Getting Started guide](https://dexidp.io/docs/getting-started/)
to install Dex.

Edit `examples/config-dev.yaml` config file from the Dex repo to add a client:

```yaml
staticClients:
- id: synapse
  secret: secret
  redirectURIs:
  - '[synapse public baseurl]/_synapse/client/oidc/callback'
  name: 'Synapse'
```

Run with `dex serve examples/config-dev.yaml`.

Synapse config:

```yaml
oidc_providers:
  - idp_id: dex
    idp_name: "My Dex server"
    skip_verification: true # This is needed as Dex is served on an insecure endpoint
    issuer: "http://127.0.0.1:5556/dex"
    client_id: "synapse"
    client_secret: "secret"
    scopes: ["openid", "profile"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.name }}"
        display_name_template: "{{ user.name|capitalize }}"
```

### Django OAuth Toolkit

[django-oauth-toolkit](https://github.com/jazzband/django-oauth-toolkit) is a
Django application providing out of the box all the endpoints, data and logic
needed to add OAuth2 capabilities to your Django projects. It supports
[OpenID Connect too](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html).

Configuration on Django's side:

1. Add an application: `https://example.com/admin/oauth2_provider/application/add/` and choose parameters like this:
* `Redirect uris`: `https://synapse.example.com/_synapse/client/oidc/callback`
* `Client type`: `Confidential`
* `Authorization grant type`: `Authorization code`
* `Algorithm`: `HMAC with SHA-2 256`
2. You can [customize the claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#customizing-the-oidc-responses) Django gives to synapse (optional):
   <details>
    <summary>Code sample</summary>

    ```python
    class CustomOAuth2Validator(OAuth2Validator):

        def get_additional_claims(self, request):
            return {
                "sub": request.user.email,
                "email": request.user.email,
                "first_name": request.user.first_name,
                "last_name": request.user.last_name,
            }
    ```
   </details>
Your synapse config is then:

```yaml
oidc_providers:
  - idp_id: django_example
    idp_name: "Django Example"
    issuer: "https://example.com/o/"
    client_id: "your-client-id"  # CHANGE ME
    client_secret: "your-client-secret"  # CHANGE ME
    scopes: ["openid"]
    user_profile_method: "userinfo_endpoint"  # needed because oauth-toolkit does not include user information in the authorization response
    user_mapping_provider:
      config:
        localpart_template: "{{ user.email.split('@')[0] }}"
        display_name_template: "{{ user.first_name }} {{ user.last_name }}"
        email_template: "{{ user.email }}"
```

### Facebook

0. You will need a Facebook developer account. You can register for one
   [here](https://developers.facebook.com/async/registration/).
1. On the [apps](https://developers.facebook.com/apps/) page of the developer
   console, "Create App", and choose "Build Connected Experiences".
2. Once the app is created, add "Facebook Login" and choose "Web". You don't
   need to go through the whole form here.
3. In the left-hand menu, open "Products"/"Facebook Login"/"Settings".
   * Add `[synapse public baseurl]/_synapse/client/oidc/callback` as an OAuth Redirect
     URL.
4. In the left-hand menu, open "Settings/Basic". Here you can copy the "App ID"
   and "App Secret" for use below.

Synapse config:

```yaml
  - idp_id: facebook
    idp_name: Facebook
    idp_brand: "facebook"  # optional: styling hint for clients
    discover: false
    issuer: "https://www.facebook.com"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    scopes: ["openid", "email"]
    authorization_endpoint: "https://facebook.com/dialog/oauth"
    token_endpoint: "https://graph.facebook.com/v9.0/oauth/access_token"
    jwks_uri: "https://www.facebook.com/.well-known/oauth/openid/jwks/"
    user_mapping_provider:
      config:
        display_name_template: "{{ user.name }}"
        email_template: "{{ user.email }}"
```

Relevant documents:
 * [Manually Build a Login Flow](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow)
 * [Using Facebook's Graph API](https://developers.facebook.com/docs/graph-api/using-graph-api/)
 * [Reference to the User endpoint](https://developers.facebook.com/docs/graph-api/reference/user)

Facebook do have an [OIDC discovery endpoint](https://www.facebook.com/.well-known/openid-configuration),
but it has a `response_types_supported` which excludes "code" (which we rely on, and
is even mentioned in their [documentation](https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#login)),
so we have to disable discovery and configure the URIs manually.

### GitHub

[GitHub][github-idp] is a bit special as it is not an OpenID Connect compliant provider, but
just a regular OAuth2 provider.

The [`/user` API endpoint](https://developer.github.com/v3/users/#get-the-authenticated-user)
can be used to retrieve information on the authenticated user. As the Synapse
login mechanism needs an attribute to uniquely identify users, and that endpoint
does not return a `sub` property, an alternative `subject_claim` has to be set.

1. Create a new OAuth application: [https://github.com/settings/applications/new](https://github.com/settings/applications/new).
2. Set the callback URL to `[synapse public baseurl]/_synapse/client/oidc/callback`.

Synapse config:

```yaml
oidc_providers:
  - idp_id: github
    idp_name: Github
    idp_brand: "github"  # optional: styling hint for clients
    discover: false
    issuer: "https://github.com/"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    authorization_endpoint: "https://github.com/login/oauth/authorize"
    token_endpoint: "https://github.com/login/oauth/access_token"
    userinfo_endpoint: "https://api.github.com/user"
    scopes: ["read:user"]
    user_mapping_provider:
      config:
        subject_claim: "id"
        localpart_template: "{{ user.login }}"
        display_name_template: "{{ user.name }}"
```

### GitLab

1. Create a [new application](https://gitlab.com/profile/applications).
2. Add the `read_user` and `openid` scopes.
3. Add this Callback URL: `[synapse public baseurl]/_synapse/client/oidc/callback`

Synapse config:

```yaml
oidc_providers:
  - idp_id: gitlab
    idp_name: Gitlab
    idp_brand: "gitlab"  # optional: styling hint for clients
    issuer: "https://gitlab.com/"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    client_auth_method: "client_secret_post"
    scopes: ["openid", "read_user"]
    user_profile_method: "userinfo_endpoint"
    user_mapping_provider:
      config:
        localpart_template: '{{ user.nickname }}'
        display_name_template: '{{ user.name }}'
```

### Gitea

Gitea is, like Github, not an OpenID provider, but just an OAuth2 provider.

The [`/user` API endpoint](https://try.gitea.io/api/swagger#/user/userGetCurrent)
can be used to retrieve information on the authenticated user. As the Synapse
login mechanism needs an attribute to uniquely identify users, and that endpoint
does not return a `sub` property, an alternative `subject_claim` has to be set.

1. Create a new application.
2. Add this Callback URL: `[synapse public baseurl]/_synapse/client/oidc/callback`

Synapse config:

```yaml
oidc_providers:
  - idp_id: gitea
    idp_name: Gitea
    discover: false
    issuer: "https://your-gitea.com/"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    client_auth_method: client_secret_post
    scopes: [] # Gitea doesn't support Scopes
    authorization_endpoint: "https://your-gitea.com/login/oauth/authorize"
    token_endpoint: "https://your-gitea.com/login/oauth/access_token"
    userinfo_endpoint: "https://your-gitea.com/api/v1/user"
    user_mapping_provider:
      config:
        subject_claim: "id"
        localpart_template: "{{ user.login }}"
        display_name_template: "{{ user.full_name }}"
```

### Google

[Google][google-idp] is an OpenID certified authentication and authorisation provider.

1. Set up a project in the Google API Console (see 
   [documentation](https://developers.google.com/identity/protocols/oauth2/openid-connect#appsetup)).
3. Add an "OAuth Client ID" for a Web Application under "Credentials".
4. Copy the Client ID and Client Secret, and add the following to your synapse config:
   ```yaml
   oidc_providers:
     - idp_id: google
       idp_name: Google
       idp_brand: "google"  # optional: styling hint for clients
       issuer: "https://accounts.google.com/"
       client_id: "your-client-id" # TO BE FILLED
       client_secret: "your-client-secret" # TO BE FILLED
       scopes: ["openid", "profile", "email"] # email is optional, read below
       user_mapping_provider:
         config:
           localpart_template: "{{ user.given_name|lower }}"
           display_name_template: "{{ user.name }}"
           email_template: "{{ user.email }}" # needs "email" in scopes above
   ```
4. Back in the Google console, add this Authorized redirect URI: `[synapse
   public baseurl]/_synapse/client/oidc/callback`.

### Keycloak

[Keycloak][keycloak-idp] is an opensource IdP maintained by Red Hat.

Keycloak supports OIDC Back-Channel Logout, which sends logout notification to Synapse, so that Synapse users get logged out when they log out from Keycloak.
This can be optionally enabled by setting `backchannel_logout_enabled` to `true` in the Synapse configuration, and by setting the "Backchannel Logout URL" in Keycloak.

Follow the [Getting Started Guide](https://www.keycloak.org/guides) to install Keycloak and set up a realm.

1. Click `Clients` in the sidebar and click `Create`

2. Fill in the fields as below:

| Field | Value |
|-----------|-----------|
| Client ID | `synapse` |
| Client Protocol | `openid-connect` |

3. Click `Save`
4. Fill in the fields as below:

| Field | Value |
|-----------|-----------|
| Client ID | `synapse` |
| Enabled | `On` |
| Client Protocol | `openid-connect` |
| Access Type | `confidential` |
| Valid Redirect URIs | `[synapse public baseurl]/_synapse/client/oidc/callback` |
| Backchannel Logout URL (optional) | `[synapse public baseurl]/_synapse/client/oidc/backchannel_logout` |
| Backchannel Logout Session Required (optional) | `On` |

5. Click `Save`
6. On the Credentials tab, update the fields:

| Field | Value |
|-------|-------|
| Client Authenticator | `Client ID and Secret` |

7. Click `Regenerate Secret`
8. Copy Secret

```yaml
oidc_providers:
  - idp_id: keycloak
    idp_name: "My KeyCloak server"
    issuer: "https://127.0.0.1:8443/realms/{realm_name}"
    client_id: "synapse"
    client_secret: "copy secret generated from above"
    scopes: ["openid", "profile"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
    backchannel_logout_enabled: true # Optional
```

### LemonLDAP

[LemonLDAP::NG][lemonldap] is an open-source IdP solution.

1. Create an OpenID Connect Relying Parties in LemonLDAP::NG
2. The parameters are:
- Client ID under the basic menu of the new Relying Parties (`Options > Basic >
  Client ID`)
- Client secret (`Options > Basic > Client secret`)
- JWT Algorithm: RS256 within the security menu of the new Relying Parties
  (`Options > Security > ID Token signature algorithm` and `Options > Security >
  Access Token signature algorithm`)
- Scopes: OpenID, Email and Profile
- Allowed redirection addresses for login (`Options > Basic > Allowed
  redirection addresses for login` ) :
  `[synapse public baseurl]/_synapse/client/oidc/callback`

Synapse config:
```yaml
oidc_providers:
  - idp_id: lemonldap
    idp_name: lemonldap
    discover: true
    issuer: "https://auth.example.org/" # TO BE FILLED: replace with your domain
    client_id: "your client id" # TO BE FILLED
    client_secret: "your client secret" # TO BE FILLED
    scopes:
      - "openid"
      - "profile"
      - "email"
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}}"
        # TO BE FILLED: If your users have names in LemonLDAP::NG and you want those in Synapse, this should be replaced with user.name|capitalize or any valid filter.
        display_name_template: "{{ user.preferred_username|capitalize }}"
```

### Mastodon

[Mastodon](https://docs.joinmastodon.org/) instances provide an [OAuth API](https://docs.joinmastodon.org/spec/oauth/), allowing those instances to be used as a single sign-on provider for Synapse.

The first step is to register Synapse as an application with your Mastodon instance, using the [Create an application API](https://docs.joinmastodon.org/methods/apps/#create) (see also [here](https://docs.joinmastodon.org/client/token/)). There are several ways to do this, but in the example below we are using CURL.

This example assumes that:
* the Mastodon instance website URL is `https://your.mastodon.instance.url`, and
* Synapse will be registered as an app named `my_synapse_app`.

Send the following request, substituting the value of `synapse_public_baseurl` from your Synapse installation.
```sh
curl -d "client_name=my_synapse_app&redirect_uris=https://[synapse_public_baseurl]/_synapse/client/oidc/callback" -X POST https://your.mastodon.instance.url/api/v1/apps
```

You should receive a response similar to the following. Make sure to save it.
```json
{"client_id":"someclientid_123","client_secret":"someclientsecret_123","id":"12345","name":"my_synapse_app","redirect_uri":"https://[synapse_public_baseurl]/_synapse/client/oidc/callback","website":null,"vapid_key":"somerandomvapidkey_123"}
```

As the Synapse login mechanism needs an attribute to uniquely identify users, and Mastodon's endpoint does not return a `sub` property, an alternative `subject_template` has to be set. Your Synapse configuration should include the following:

```yaml
oidc_providers:
  - idp_id: my_mastodon
    idp_name: "Mastodon Instance Example"
    discover: false
    issuer: "https://your.mastodon.instance.url/@admin"
    client_id: "someclientid_123"    
    client_secret: "someclientsecret_123"
    authorization_endpoint: "https://your.mastodon.instance.url/oauth/authorize"
    token_endpoint: "https://your.mastodon.instance.url/oauth/token"
    userinfo_endpoint: "https://your.mastodon.instance.url/api/v1/accounts/verify_credentials"
    scopes: ["read"]
    user_mapping_provider:
      config:
        subject_template: "{{ user.id }}"
        localpart_template: "{{ user.username }}"
        display_name_template: "{{ user.display_name }}"
```

Note that the fields `client_id` and `client_secret` are taken from the CURL response above.

### Shibboleth with OIDC Plugin

[Shibboleth](https://www.shibboleth.net/) is an open Standard IdP solution widely used by Universities.

1. Shibboleth needs the [OIDC Plugin](https://shibboleth.atlassian.net/wiki/spaces/IDPPLUGINS/pages/1376878976/OIDC+OP) installed and working correctly.
2. Create a new config on the IdP Side, ensure that the `client_id` and `client_secret`
   are randomly generated data.
```json
{
    "client_id": "SOME-CLIENT-ID",
    "client_secret": "SOME-SUPER-SECRET-SECRET",
    "response_types": ["code"],
    "grant_types": ["authorization_code"],
    "scope": "openid profile email",
    "redirect_uris": ["https://[synapse public baseurl]/_synapse/client/oidc/callback"]
}
```

Synapse config:

```yaml
oidc_providers:
  # Shibboleth IDP
  #
  - idp_id: shibboleth
    idp_name: "Shibboleth Login"
    discover: true
    issuer: "https://YOUR-IDP-URL.TLD"
    client_id: "YOUR_CLIENT_ID"
    client_secret: "YOUR-CLIENT-SECRECT-FROM-YOUR-IDP"
    scopes: ["openid", "profile", "email"]
    allow_existing_users: true
    user_profile_method: "userinfo_endpoint"
    user_mapping_provider:
      config:
        subject_claim: "sub"
        localpart_template: "{{ user.sub.split('@')[0] }}"
        display_name_template: "{{ user.name }}"
        email_template: "{{ user.email }}"
```

### Twitch

1. Setup a developer account on [Twitch](https://dev.twitch.tv/)
2. Obtain the OAuth 2.0 credentials by [creating an app](https://dev.twitch.tv/console/apps/)
3. Add this OAuth Redirect URL: `[synapse public baseurl]/_synapse/client/oidc/callback`

Synapse config:

```yaml
oidc_providers:
  - idp_id: twitch
    idp_name: Twitch
    issuer: "https://id.twitch.tv/oauth2/"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    client_auth_method: "client_secret_post"
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
```

### Twitter

*Using Twitter as an identity provider requires using Synapse 1.75.0 or later.*

1. Setup a developer account on [Twitter](https://developer.twitter.com/en/portal/dashboard)
2. Create a project & app.
3. Enable user authentication and under "Type of App" choose "Web App, Automated App or Bot".
4. Under "App info" set the callback URL to `[synapse public baseurl]/_synapse/client/oidc/callback`.
5. Obtain the OAuth 2.0 credentials under the "Keys and tokens" tab, copy the "OAuth 2.0 Client ID and Client Secret"

Synapse config:

```yaml
oidc_providers:
  - idp_id: twitter
    idp_name: Twitter
    idp_brand: "twitter"  # optional: styling hint for clients
    discover: false  # Twitter is not OpenID compliant.
    issuer: "https://twitter.com/"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    pkce_method: "always"
    # offline.access providers refresh tokens, tweet.read and users.read needed for userinfo request.
    scopes: ["offline.access", "tweet.read", "users.read"]
    authorization_endpoint: https://twitter.com/i/oauth2/authorize
    token_endpoint: https://api.twitter.com/2/oauth2/token
    userinfo_endpoint: https://api.twitter.com/2/users/me?user.fields=profile_image_url
    user_mapping_provider:
      config:
        subject_template: "{{ user.data.id }}"
        localpart_template: "{{ user.data.username }}"
        display_name_template: "{{ user.data.name }}"
        picture_template: "{{ user.data.profile_image_url }}"
```

### XWiki

Install [OpenID Connect Provider](https://extensions.xwiki.org/xwiki/bin/view/Extension/OpenID%20Connect/OpenID%20Connect%20Provider/) extension in your [XWiki](https://www.xwiki.org) instance.

Synapse config:

```yaml
oidc_providers:
  - idp_id: xwiki
    idp_name: "XWiki"
    issuer: "https://myxwikihost/xwiki/oidc/"
    client_id: "your-client-id" # TO BE FILLED
    client_auth_method: none
    scopes: ["openid", "profile"]
    user_profile_method: "userinfo_endpoint"
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
```
