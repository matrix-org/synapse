import React from 'react';

import style from '../../less/main.less';

import ButtonDisplay from './ButtonDisplay';
import ContentWrapper from '../containers/ContentWrapper';

const tlsLink = "https://en.wikipedia.org/wiki/Transport_Layer_Security";
const apacheLink = "http://httpd.apache.org/";
const caddyLink = "https://caddyserver.com/";
const haproxyLink = "http://www.haproxy.org/";
const nginxLink = "https://www.nginx.com/";
const proxyInfoLink = "https://github.com/matrix-org/synapse/blob/master/docs/reverse_proxy.rst";

export default ({ onClickACME, onClickTLS, onClickReverseProxy }) =>
  <ContentWrapper>
    <h1>TLS</h1>
    <p>
      I was going to make a <a target="_blank" href={tlsLink}>TLS</a> joke but it
    was making me insecure..
    </p>
    <p>
      TLS keeps the communication between homeservers secure. To enable TLS you'll
      need a TLS cert. You can use ACME, provide your own certs, or let the reverse
      proxy handle the TLS certs instead.
    </p>
    <h3>
      ReverseProxy
    </h3>
    <p>
      It is a good idea to use Synapse behind a reverse proxy such as <a target="_blank" href={apacheLink}>Apache</a>, <a target="_blank" href={caddyLink}>Caddy</a>, <a target="_blank" href={haproxyLink}>HAProxy</a>, or <a target="_blank" href={nginxLink}>NGiNX</a>.
    </p>
    <p>
      The main benefit to this is that the reverse proxy can listen on the privilaged port
      443 (which clients like riot expect to connect to) on behalf of synapse. The incoming traffic
      is then forwarded to Synapse on a non privilaged port.
      <br />
      You need root to listen on ports 0 to 1024 inclusive and
      running synapse with root privileges is <b>strongly discouraged</b>.
      Reverse proxies are more secure, run with root and pass things on like nobody's business.
      <br />
      (Note: you can also have synapse use a non privilaged port
      by using one of the delegation methods mentioned earlier.)
    </p>
    <p>
      If you choose to use a Reverse Proxy (good for you) we'll provide you with
      configuration templates later. Easy breasy.
    </p>
    <p>
      More information about Reverse Proxies <a target="_blank" href={proxyInfoLink}> in the docs.</a>
    </p>
    <h3>
      ACME
    </h3>
    <p>
      ACME is <strike>a super cool initiative</strike> a protocol that allows TLS
      certificates to be requested automagically. Synapse supports ACME by requesting
      certs from Let's Encrypt. This is the easiest way to manage your certs because
      once you set it up you don't need to manage it.
    </p>
    <p>
      If you wish to use ACME you will need access to port 80 which usually requires
      root privileges. Do not run Synapse as root. Use a Reverse Proxy or Authbind
    </p>
    <h3>
      Provide your own TLS certs
    </h3>
    <p>
      If you have your own TLS certs for the domain we'll ask you for the path
      to them or you can upload them for synapse to use.
    </p>
    <ButtonDisplay>
      <button onClick={() => onClickACME()}>Use ACME</button>
      <button onClick={() => onClickReverseProxy()}>I already/will use a Reverse Proxy with TLS</button>
      <button onClick={() => onClickTLS()}>I have a TLS cert</button>
    </ButtonDisplay>
  </ContentWrapper>