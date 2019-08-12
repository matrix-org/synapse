import React from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';

import ButtonDisplay from './ButtonDisplay';
import DownloadOrCopy from './DownloadOrCopy';

import { KEY_EXPORT_UI } from '../reducers/ui_constants';


export default ({ secret_key_loaded, secret_key, onClick }) => {
  var body;
  if (!secret_key_loaded) {
    body = <Card.Body>Generating secret key</Card.Body>
  } else {
    body = <Card.Body>
      <p>
        Your server uses a secret key to identify itself to other servers. Keep
        a copy of it to retain ownership of the server name in case the server
        is inaccessible:
      </p>
      <pre><code>{secret_key}</code></pre>
      <p>Keep a copy of this key somewhere safe</p>
      <DownloadOrCopy content={secret_key} fileName="secret_key.txt" />
      <ButtonDisplay><button onClick={onClick}>Next</button></ButtonDisplay>
    </Card.Body>
  }

  return <Card>
    <Accordion.Toggle as={Card.Header} eventKey={KEY_EXPORT_UI}>
      Secret Key
    </Accordion.Toggle>
    <Accordion.Collapse eventKey={KEY_EXPORT_UI}>
      {body}
    </Accordion.Collapse>
  </Card>
}