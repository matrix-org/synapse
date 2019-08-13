import React, { useState } from 'react';

import style from '../../scss/main.scss';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import Tabs from 'react-bootstrap/Tabs';
import Tab from 'react-bootstrap/Tab';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import { DELEGATION_TYPES } from '../actions/constants';
import { DELEGATION_OPTIONS_UI } from '../reducers/ui_constants';
import AccordionToggle from '../containers/AccordionToggle';
import { next_ui } from '../reducers/setup-ui-reducer';

export default ({ servername, skip, onClick }) => {
  const defaultType = DELEGATION_TYPES.DNS;
  const [type, setType] = useState(defaultType);

  const [delegatedServername, setDelegatedServerName] = useState("");

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

  const toggle = useAccordionToggle(next_ui(DELEGATION_OPTIONS_UI));

  return <Card>
    <AccordionToggle as={Card.Header} eventKey={DELEGATION_OPTIONS_UI}>
      Delegation (optional)
      <button onClick={() => {
        toggle();
        skip();
      }}>
        Skip
      </button>
    </AccordionToggle>
    <Accordion.Collapse eventKey={DELEGATION_OPTIONS_UI}>
      <Card.Body>
        <p>
          If you'd like your synapse to be hosted on a different server to the
          one known on the network by '{servername}' you can use delegation.
        </p>
        <a href="https://github.com/matrix-org/synapse/blob/master/docs/federate.md" target="_blank">
          Learn more
        </a>
        <p>
          Other federation servers will connect to {servername}:8448 over the network.
        </p>
        <p>
          There are two forms of delegation:
        </p>

        <Tabs defaultActiveKey={defaultType} onSelect={k => setType(k)}>
          <Tab eventKey={DELEGATION_TYPES.DNS} title={DELEGATION_TYPES.DNS}>
            <p>
              You will need access to {servername}'s domain zone DNS records.
              This method also requires the synapse install's server to provide
              a valid TLS cert for {servername}
            </p>
            <p>
              You will need to add an SRV record to {servername}'s DNS zone. (Once
              again, we'll print the SRV record out for you later.)
            </p>
          </Tab>
          <Tab eventKey={DELEGATION_TYPES.WELL_KNOWN} title={DELEGATION_TYPES.WELL_KNOWN}>
            <p>
              {servername} provides the url
              https://{servername}/.well-known/matrix/server which gives
              federating servers information about how to contact the actual
              server hosting the synapse install. (Don't worry! We'll print out
              the .well-known file for you later.)
            </p>
          </Tab>
        </Tabs>

        <p>Please enter the domain name of the server synapse is installed on.</p>
        <input
          type="text"
          onChange={e => setDelegatedServerName(e.target.value)}
          autoFocus
          placeholder="Enter server name"
        />

        <p>
          Homeserver Port
        </p>
        <input
          type="text"
          onChange={onFederationChange}
          className={fedPortValid ? undefined : style.invalidInput}
          autoFocus
          placeholder="Use Default 8448"
        />
        <p>
          Client Port
        </p>
        <input
          type="text"
          onChange={onClientChange}
          className={clientPortValid ? undefined : style.invalidInput}
          autoFocus
          placeholder="Use Default 443"
        />

        <button disabled={delegatedServername && clientPortValid && fedPortValid ? undefined : true}
          onClick={() => {
            toggle();
            onClick(type, delegatedServername, fedPort, clientPort)
          }}
        >
          Use {type}
        </button>

      </Card.Body>
    </Accordion.Collapse>
  </Card>
}