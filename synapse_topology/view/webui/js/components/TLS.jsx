import React from 'react';

import style from '../../less/main.less';

import ButtonDisplay from './ButtonDisplay';
import ContentWrapper from '../containers/ContentWrapper';

const tlsLink = "https://en.wikipedia.org/wiki/Transport_Layer_Security";

export default ({ onClickACME, onClickTLS, onClickNoTLS }) =>
  <ContentWrapper>
    <h1>TLS</h1>
    <p>
      I was going to make a <a target="_blank" href={tlsLink}>TLS</a> joke but
    was making me insecure..
    </p>
    <p>
      TLS keeps the communication between homeservers secure. To enable TLS you'll
      need a TLS cert. You can use ACME, provide your own certs, or let the reverse
      proxy handle the TLS certs instead. (You can also not use TLS but that's not recommended)
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
    <h3>
      Provide your own
    </h3>
    <p>
      If you have your own TLS certs for the domain name you can specify a path
      to them or you can upload them for synapse to use.
    </p>
    <h3>
      ReverseProxy
    </h3>
    <p>
      Using a ReverseProxy is considered a very good idea.
    </p>
    <h3>
      Don't use TLS
    </h3>
    <p>
      Please don't do this.
    </p>
    <ButtonDisplay>
      <button onClick={() => onClickACME()}>Use ACME</button>
      <button onClick={() => onClickTLS()}>I have a TLS cert</button>
      <button onClick={() => onClickReverseProxy()}>Use a Reverse Proxy</button>
    </ButtonDisplay>
    <button className={style.redButton} onClick={() => onClickNoTLS()}>Do not use TLS</button>
  </ContentWrapper >