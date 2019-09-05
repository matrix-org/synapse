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
import Tabs from 'react-bootstrap/Tabs';
import Tab from 'react-bootstrap/Tab';

export default ({
    onClick,
}) => {

    const defaultDatabase = DATABASE_TYPES.POSTGRES;
    const [database, setDatabase] = useState(defaultDatabase)

    const hostDefault = "localhost"
    const [databaseHost, setHost] = useState(hostDefault);
    const [postgresDatabase, setPostgresDatabase] = useState();
    const [databaseUsername, setUser] = useState();
    const [databasePassword, setPassword] = useState();

    const toggle = useAccordionToggle(nextUI(DATABASE_UI));

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={DATABASE_UI}>
            Database
        </AccordionToggle>
        <Accordion.Collapse eventKey={DATABASE_UI}>
            <Card.Body>
                <p>Synapse can use either SQLite3 or Postgres as it's database.</p>
                <p>Postgres is recommended.</p>

                <Tabs defaultActiveKey={defaultDatabase} onSelect={k => setDatabase(k)}>
                    <Tab eventKey={DATABASE_TYPES.POSTGRES} title={"Postgres"}>
                        This will connect to the given Postgres database via {DATABASE_TYPES.POSTGRES}
                        <p>
                            Host
                        </p>
                        <input
                            type="text"
                            onChange={e => setHost(e.target.value ? e.target.value : hostDefault)}
                            autoFocus
                            placeholder="localhost"
                        />
                        <p>
                            Database name
                        </p>
                        <input
                            type="text"
                            onChange={e => setPostgresDatabase(e.target.value)}
                            autoFocus
                            placeholder="unspecified"
                        />
                        <p>
                            User name
                        </p>
                        <input
                            type="text"
                            onChange={e => setUser(e.target.value)}
                            autoFocus
                            placeholder="unspecified"
                        />
                        <p>
                            Password
                        </p>
                        <input
                            type="text"
                            onChange={e => setPassword(e.target.value)}
                            autoFocus
                            placeholder="unspecified"
                        />
                        <button
                            className='inputButton'
                            disabled={databaseHost ? undefined : true}
                            onClick={() => {
                                toggle();
                                onClick({
                                    databaseType: DATABASE_TYPES.POSTGRES,
                                    databaseHost,
                                    database: postgresDatabase,
                                    databaseUsername,
                                    databasePassword,
                                })
                            }}
                        >Use Postgres</button>
                    </Tab>
                    <Tab eventKey={DATABASE_TYPES.SQLITE3} title={DATABASE_TYPES.SQLITE3}>
                        <button
                            className='inputButton'
                            onClick={() => {
                                toggle();
                                onClick({
                                    databaseType: DATABASE_TYPES.SQLITE3
                                });
                            }}
                        >Use {DATABASE_TYPES.SQLITE3}</button>
                    </Tab>
                </Tabs>
            </Card.Body>
        </Accordion.Collapse>
    </Card >

}
