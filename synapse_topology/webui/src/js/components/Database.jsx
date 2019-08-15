import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import {
    DATABASE_TYPES,
} from '../actions/constants'

import { DATABASE_UI } from '../reducers/ui-constants';

import AccordionToggle from '../containers/AccordionToggle';

import { nextUI } from '../reducers/setup-ui-reducer';

export default ({
    onClick,
}) => {

    const defaultDatabase = DATABASE_TYPES.POSTGRES;
    const [database, setDatabase] = useState(defaultDatabase)

    const toggle = useAccordionToggle(nextUI(DATABASE_UI));

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={DATABASE_UI}>
            Database
        </AccordionToggle>
        <Accordion.Collapse eventKey={DATABASE_UI}>
            <Card.Body>
                <p>Synapse can use either SQLite3 or Postgres as it's database.</p>
                <p>Postgres is recommended</p>

                <select defaultValue={defaultDatabase}
                    onChange={event => setDatabase(event.target.value)}
                >
                    <option value={DATABASE_TYPES.POSTGRES}>PostgreSQL</option>
                    <option value={DATABASE_TYPES.SQLITE3}>SQLite3</option>
                </select>
                <button onClick={() => {

                    toggle();
                    onClick(database)

                }}>Next</button>
            </Card.Body>
        </Accordion.Collapse>
    </Card>

}
