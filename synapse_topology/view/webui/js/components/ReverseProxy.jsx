import React, { useState } from 'react';

import ContentWrapper from './ContentWrapper';

import {
  REVERSE_PROXY_TYPES
} from '../actions/constants'

export default ({ onClick }) => {
  const [reverseProxy, setReverseProxy] = useState(REVERSE_PROXY_TYPES.NONE);

  const onChange = event => {
    setReverseProxy(event.target.value);
  }

  return <ContentWrapper>
    <h1>Reverse Proxy</h1>
    <select>
      <option value={REVERSE_PROXY_TYPES.NONE} selected>I will either not use a Reverse Proxy or I will do something weird.</option>
      <option value={REVERSE_PROXY_TYPES.APACHE}>Apache</option>
      <option value={REVERSE_PROXY_TYPES.CADDY}>Caddy</option>
      <option value={REVERSE_PROXY_TYPES.HAPROXY}>HaProxy</option>
      <option value={REVERSE_PROXY_TYPES.NGINX}>NGINX</option>
    </select>
    <div>
      <button onClick={() => onClick(reverseProxy)}>I like it</button>
    </div>
  </ContentWrapper>
}