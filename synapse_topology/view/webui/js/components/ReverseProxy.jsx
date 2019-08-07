import React, { useState } from 'react';

import ContentWrapper from '../containers/ContentWrapper';

import {
  REVERSE_PROXY_TYPES
} from '../actions/constants'


export default ({ onClick }) => {
  const defaultValue = REVERSE_PROXY_TYPES.NGINX;
  const [reverseProxy, setReverseProxy] = useState(defaultValue);

  const onChange = event => {
    console.log("trigered")
    console.log(event.target)
    setReverseProxy(event.target.value);
  }

  return <ContentWrapper>
    <h1>Reverse Proxy</h1>
    <p>
      Please choose the reverse proxy you're using. This is just so we can provide
      you with a template later, if you already know how you're going to set yours
      up don't worry too much about this.
    </p>
    <select defaultValue={defaultValue} onChange={onChange} >
      <option value={REVERSE_PROXY_TYPES.APACHE}>Apache</option>
      <option value={REVERSE_PROXY_TYPES.CADDY}>Caddy</option>
      <option value={REVERSE_PROXY_TYPES.HAPROXY}>HAProxy</option>
      <option value={REVERSE_PROXY_TYPES.NGINX}>NGiNX</option>
      <option value={REVERSE_PROXY_TYPES.OTHER}>Some other Reverse Proxy</option>
    </select>
    <div>
      <button onClick={() => onClick(reverseProxy)}>Safety First</button>
    </div>
  </ContentWrapper>
}