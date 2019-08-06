import React, { useState } from 'react';

import ContentWrapper from './ContentWrapper';

import style from '../../less/main.less';

export default ({ onClick }) => {
  const [fedPort, setFedPort] = useState("");
  const [clientPort, setClientPort] = useState("");
  const [clientPortValid, setClientPortValid] = useState(true)
  const [fedPortValid, setFedPortValid] = useState(true)

  const updateValidity = (port, setValid) => setValid(
    !port ||
    (!isNaN(port) && 0 < port && port <= 65535)
  )

  const onFederationChange = event => {
    const val = event.target.value;
    setFedPort(val);
    updateValidity(val, setFedPortValid);
  }

  const onClientChange = event => {
    const val = event.target.value;
    setClientPort(val);
    updateValidity(val, setClientPortValid);
  }

  return <ContentWrapper>
    <h1>Outward facing ports</h1>
    <p>
      Normally other matrix servers will try to contact the Synapse install's server on
      port 8448 and clients, such as riot, riotX, neo etc., will try to contact
      the install server on port 443.
    </p>
    <p>
      Delegation let's us tell those servers and clients to try a different port!
      (Flexible!)
    </p>
    <p>
      It's perfectly fine to leave the defaults. Only change them if you have a
      real need to.
    </p>
    <p>
      I would recommend using unprivileged ports but I would recommend the
      default ports more strongly.
    </p>
    <p>
      Please choose the port for other matrix servers to contact:
    </p>
    <input
      type="text"
      onChange={onFederationChange}
      className={fedPortValid ? undefined : style.invalidInput}
      autoFocus
      placeholder="Use Default 8448"
    ></input>
    <p>
      Please choose the port for clients to contact:
    </p>
    <input
      type="text"
      onChange={onClientChange}
      className={clientPortValid ? undefined : style.invalidInput}
      autoFocus
      placeholder="Use Default 443"
    ></input>
    <div>
      <button
        disabled={clientPortValid && fedPortValid ? undefined : true}
        onClick={() => onClick(fedPort, clientPort)}
      >Use These Ports</button>
    </div>
  </ContentWrapper>
}