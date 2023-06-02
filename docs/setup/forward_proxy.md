# Using a forward proxy with Synapse

You can use Synapse with a forward or outbound proxy. An example of when
this is necessary is in corporate environments behind a DMZ (demilitarized zone).
Synapse supports routing outbound HTTP(S) requests via a proxy. Only HTTP(S)
proxy is supported, not SOCKS proxy or anything else.

## Configure

The `http_proxy`, `https_proxy`, `no_proxy` environment variables are used to
specify proxy settings. The environment variable is not case sensitive.
- `http_proxy`: Proxy server to use for HTTP requests.
- `https_proxy`: Proxy server to use for HTTPS requests.
- `no_proxy`: Comma-separated list of hosts, IP addresses, or IP ranges in CIDR
  format which should not use the proxy. Synapse will directly connect to these hosts.

The `http_proxy` and `https_proxy` environment variables have the form: `[scheme://][<username>:<password>@]<host>[:<port>]`
- Supported schemes are `http://` and `https://`. The default scheme is `http://`
  for compatibility reasons; it is recommended to set a scheme. If scheme is set
  to `https://` the connection uses TLS between Synapse and the proxy.

  **NOTE**: Synapse validates the certificates. If the certificate is not
  valid, then the connection is dropped.
- Default port if not given is `1080`.
- Username and password are optional and will be used to authenticate against
  the proxy.

**Examples**
- HTTP_PROXY=http://USERNAME:PASSWORD@10.0.1.1:8080/
- HTTPS_PROXY=http://USERNAME:PASSWORD@proxy.example.com:8080/
- NO_PROXY=master.hostname.example.com,10.1.0.0/16,172.30.0.0/16

**NOTE**:
Synapse does not apply the IP blacklist to connections through the proxy (since
the DNS resolution is done by the proxy). It is expected that the proxy or firewall
will apply blacklisting of IP addresses.

## Connection types

The proxy will be **used** for:

- push
- url previews
- phone-home stats
- recaptcha validation
- CAS auth validation
- OpenID Connect
- Outbound federation
- Federation (checking public key revocation)
- Fetching public keys of other servers
- Downloading remote media

It will **not be used** for:

- Application Services
- Identity servers
- In worker configurations
  - connections between workers
  - connections from workers to Redis

## Troubleshooting

If a proxy server is used with TLS (HTTPS) and no connections are established,
it is most likely due to the proxy's certificates. To test this, the validation
in Synapse can be deactivated.

**NOTE**: This has an impact on security and is for testing purposes only!

To deactivate the certificate validation, the following setting must be added to
your [homserver.yaml](../usage/configuration/homeserver_sample_config.md).

```yaml
use_insecure_ssl_client_just_for_testing_do_not_use: true
```
