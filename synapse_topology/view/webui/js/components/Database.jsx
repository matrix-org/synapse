import React, { useState } from 'react';

import ContentWrapper from '../containers/ContentWrapper';

import {
  DATABASE_TYPES
} from '../actions/constants'
import ButtonDisplay from './ButtonDisplay';

export default ({
  onClick,
}) => {
  const defaultDatabase = DATABASE_TYPES.POSTGRES;
  const [database, setDatabase] = useState(defaultDatabase)
  return <ContentWrapper>
    <h1>Database</h1>
    <p>Synapse can use either SQLite3 or Postgres as it's databse.</p>
    <p>If you don't have one of those two installed Postgres is the recommended database to use.</p>

    <select defaultValue={defaultDatabase} onChange={event => setDatabase(event.target.value)}>
      <option value={DATABASE_TYPES.POSTGRES}>PostgreSQL</option>
      <option value={DATABASE_TYPES.SQLITE3}>SQLite3</option>
    </select>
    <ButtonDisplay>
      <button onClick={() => onClick(database)}>Continue</button>
    </ButtonDisplay>
  </ContentWrapper>
}
