import React, { useState } from 'react';

import ContentWrapper from '../containers/ContentWrapper';

export default ({ onClick }) => {
  const [servername, setServerName] = useState("");

  const onChange = event => {
    setServerName(event.target.value);
  }

  return <ContentWrapper>
    <h1>Synapse install's servername.</h1>
    <p>What is the Synapse Install's server called on the network?</p>
    <input type="text" onChange={onChange} autoFocus placeholder="host.server"></input>
    <div>
      <button disabled={servername ? undefined : true} onClick={() => onClick(servername)}>Continue</button>
    </div>
  </ContentWrapper>
}