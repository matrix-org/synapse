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
setting in your configuration file (or uncomment one of the existing examples).
See [sample_config.yaml](./sample_config.yaml) for some sample settings, as well as
the text below for example configurations for specific providers.

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

### [Dex][dex-idp]

[Dex][dex-idp] is a simple, open-source, certified OpenID Connect Provider.
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
### [Keycloak][keycloak-idp]

[Keycloak][keycloak-idp] is an opensource IdP maintained by Red Hat.

Follow the [Getting Started Guide](https://www.keycloak.org/getting-started) to install Keycloak and set up a realm.

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
    issuer: "https://127.0.0.1:8443/auth/realms/{realm_name}"
    client_id: "synapse"
    client_secret: "copy secret generated from above"
    scopes: ["openid", "profile"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.preferred_username }}"
        display_name_template: "{{ user.name }}"
```
### [Auth0][auth0]

1. Create a regular web application for Synapse
2. Set the Allowed Callback URLs to `[synapse public baseurl]/_synapse/client/oidc/callback`
3. Add a rule to add the `preferred_username` claim.
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

### GitHub

GitHub is a bit special as it is not an OpenID Connect compliant provider, but
just a regular OAuth2 provider.

The [`/user` API endpoint](https://developer.github.com/v3/users/#get-the-authenticated-user)
can be used to retrieve information on the authenticated user. As the Synapse
login mechanism needs an attribute to uniquely identify users, and that endpoint
does not return a `sub` property, an alternative `subject_claim` has to be set.

1. Create a new OAuth application: https://github.com/settings/applications/new.
2. Set the callback URL to `[synapse public baseurl]/_synapse/client/oidc/callback`.

Synapse config:

```yaml
oidc_providers:
  - idp_id: github
    idp_name: Github
    idp_brand: "org.matrix.github"  # optional: styling hint for clients
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

### [Google][google-idp]

1. Set up a project in the Google API Console (see
   https://developers.google.com/identity/protocols/oauth2/openid-connect#appsetup).
2. add an "OAuth Client ID" for a Web Application under "Credentials".
3. Copy the Client ID and Client Secret, and add the following to your synapse config:
   ```yaml
   oidc_providers:
     - idp_id: google
       idp_name: Google
       idp_brand: "org.matrix.google"  # optional: styling hint for clients
       issuer: "https://accounts.google.com/"
       client_id: "your-client-id" # TO BE FILLED
       client_secret: "your-client-secret" # TO BE FILLED
       scopes: ["openid", "profile"]
       user_mapping_provider:
         config:
           localpart_template: "{{ user.given_name|lower }}"
           display_name_template: "{{ user.name }}"
   ```
4. Back in the Google console, add this Authorized redirect URI: `[synapse
   public baseurl]/_synapse/client/oidc/callback`.

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

### GitLab

1. Create a [new application](https://gitlab.com/profile/applications).
2. Add the `read_user` and `openid` scopes.
3. Add this Callback URL: `[synapse public baseurl]/_synapse/client/oidc/callback`

Synapse config:

```yaml
oidc_providers:
  - idp_id: gitlab
    idp_name: Gitlab
    idp_brand: "org.matrix.gitlab"  # optional: styling hint for clients
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

### Facebook

Like Github, Facebook provide a custom OAuth2 API rather than an OIDC-compliant
one so requires a little more configuration.

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
    idp_brand: "org.matrix.facebook"  # optional: styling hint for clients
    discover: false
    issuer: "https://facebook.com"
    client_id: "your-client-id" # TO BE FILLED
    client_secret: "your-client-secret" # TO BE FILLED
    scopes: ["openid", "email"]
    authorization_endpoint: https://facebook.com/dialog/oauth
    token_endpoint: https://graph.facebook.com/v9.0/oauth/access_token
    user_profile_method: "userinfo_endpoint"
    userinfo_endpoint: "https://graph.facebook.com/v9.0/me?fields=id,name,email,picture"
    user_mapping_provider:
      config:
        subject_claim: "id"
        display_name_template: "{{ user.name }}"
```

Relevant documents:
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow
 * Using Facebook's Graph API: https://developers.facebook.com/docs/graph-api/using-graph-api/
 * Reference to the User endpoint: https://developers.facebook.com/docs/graph-api/reference/user

### Gitea

Gitea is, like Github, not an OpenID provider, but just an OAuth2 provider.

The [`/user` API endpoint](https://try.gitea.io/api/swagger#/user/userGetCurrent)
can be used to retrieve information on the authenticated user. As the Synapse
login mechanism needs an attribute to uniquely identify users, and that endpoint
does not return a `sub` property, an alternative `subject_claim` has to be set.

1. Create a new application.
2. Add this Callback URL: `[synapse public baseurl]/_synapse/oidc/callback`

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
