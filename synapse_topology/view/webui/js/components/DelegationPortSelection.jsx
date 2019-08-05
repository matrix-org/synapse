import React, { useState } from 'react';

import ContentWrapper from './ContentWrapper';

export default ({ onClick }) => {
  const [delegationPort, setDelegationPort] = useState("");
  const [validInput, setValidInput] = useState(true);

  const onChange = event => {
    const val = event.target.value;
    setValidInput(!isNaN(event.target.value) && 0 < val && val < 65535);
    setDelegationPort(val);
  }

  return <ContentWrapper>
    <h1>Outward facing port selection</h1>
    <p>
      Normally other servers will try to contact the Synapse install's server on
      port 8448 and clients, such as riot, riotX, neo etc., will try to contact
      the install server on port 443.
    </p>
    <p>
      Delegation let's us tell those servers and clients to try a different port!
      (Flexible!)
      However, we can only specify one port. That one port will be used for both
      the servers and the clients.
    </p>
    <p>
      It's perfectly fine to leave the defaults. Only change them if you have a
      real need to.
    </p>
    <p>
      I would recommend an unprivileged port but I would recommend the default ports
      more strongly.
    </p>
    <input
      type="text"
      onChange={onChange}
      autoFocus
      placeholder="Use Defaults"
    ></input>
    <div>
      <button
        disabled={!delegationPort || validInput ? undefined : true}
        onClick={() => onClick(delegationPort)}
      >Use {delegationPort ? delegationPort : "default ports"}</button>
    </div>
  </ContentWrapper>
}