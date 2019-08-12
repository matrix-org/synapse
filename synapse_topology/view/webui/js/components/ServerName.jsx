import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import { SERVER_NAME_UI } from '../reducers/ui_constants';

export default ({ onClick }) => {
  const [servername, setServerName] = useState("");

  const onChange = event => {
    setServerName(event.target.value);
  }

  return <Card>
    <Accordion.Toggle as={Card.Header} eventKey={SERVER_NAME_UI}>
      Name your server
    </Accordion.Toggle>
    <Accordion.Collapse eventKey={SERVER_NAME_UI}>
      <Card.Body>
        <p>
          Your server name usually matches your domain. For example, the
          matrix.org server is simply called `matrix.org`.
        </p>
        <p>
          Your server name will be used to establish User IDs (e.g.
          `@user:server.name`) and Room Aliases (e.g. `#room:server.name`).
        </p>
        <input type="text" onChange={onChange} autoFocus placeholder="Enter server name"></input>
        <div>
          <button disabled={servername ? undefined : true} onClick={() => onClick(servername)}>Next</button>
        </div>
      </Card.Body>
    </Accordion.Collapse>
  </Card>;
}