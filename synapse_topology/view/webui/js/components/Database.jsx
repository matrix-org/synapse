import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';

import {
  DATABASE_TYPES
} from '../actions/constants'

import { DATABASE_UI } from '../reducers/ui_constants';

export default ({
  onClick,
}) => {
  const defaultDatabase = DATABASE_TYPES.POSTGRES;
  const [database, setDatabase] = useState(defaultDatabase)
  return <Card>
    <Accordion.Toggle as={Card.Header} eventKey={DATABASE_UI}>
      Database
    </Accordion.Toggle>
    <Accordion.Collapse eventKey={DATABASE_UI}>
      <Card.Body>
        <p>Synapse can use either SQLite3 or Postgres as it's database.</p>
        <p>Postgres is recommended</p>

        <select defaultValue={defaultDatabase} onChange={event => setDatabase(event.target.value)}>
          <option value={DATABASE_TYPES.POSTGRES}>PostgreSQL</option>
          <option value={DATABASE_TYPES.SQLITE3}>SQLite3</option>
        </select>
        <button onClick={() => onClick(database)}>Next</button>
      </Card.Body>
    </Accordion.Collapse>
  </Card>
}
