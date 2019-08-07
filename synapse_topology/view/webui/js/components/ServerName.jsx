import React, { useState } from 'react';

import ContentWrapper from '../containers/ContentWrapper';

export default ({ onClick }) => {
  const [servername, setServerName] = useState("");

  const onChange = event => {
    setServerName(event.target.value);
  }

  return <ContentWrapper>
    <h1>Select a server name</h1>
    <p>It's important to choose a good name for your server because it cannot be changed later.</p>
    <p>
      The name forms a part of the user id's for the users on the server. Which will look like `@you:server.name`.
      The name will also be what other servers look up when they're trying to reach this one.
    </p>
    <p>
      Normally the server name is usually just your domain. For example <a target="_blank" href="https://matrix.org">matrix.org</a>'s server is
      known as `matrix.org`.
    </p>
    <input type="text" onChange={onChange} autoFocus placeholder="synapse.dev"></input>
    <div>
      <button disabled={servername ? undefined : true} onClick={() => onClick(servername)}>I like it</button>
    </div>
  </ContentWrapper>;
}