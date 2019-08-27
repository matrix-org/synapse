import React, { useState } from 'react';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import ButtonDisplay from './ButtonDisplay';
import DownloadOrCopy from './DownloadOrCopy';

import { KEY_EXPORT_UI } from '../reducers/ui-constants';
import AccordionToggle from '../containers/AccordionToggle';
import { nextUI } from '../reducers/setup-ui-reducer';


export default ({ secretKeyLoaded, secretKey, onClick }) => {

    const [downloadedOrCopied, setDownloadedOrCopied] = useState(false);
    const toggle = useAccordionToggle(nextUI(KEY_EXPORT_UI));

    const decoratedOnClick = () => {

        setDownloadedOrCopied(false);
        toggle();
        onClick();

    }

    let body;

    if (!secretKeyLoaded) {

        body = <Card.Body><p>Generating secret key</p></Card.Body>

    } else {

        body = <Card.Body>
            <p>
                Your server uses a secret key to identify itself to other servers. Keep
                a copy of it to retain ownership of the server name in case the server
                is inaccessible:
            </p>
            <pre><code>{secretKey}</code></pre>
            <p>
                Keep a copy of this key somewhere safe by downloading or copying
                the key to your clipboard to continue.
            </p>
            <DownloadOrCopy
                content={secretKey}
                fileName="secret_key.txt"
                onClick={() => setDownloadedOrCopied(true)} />
            <div className='blockWrapper'>
                <ButtonDisplay>
                    <button
                        onClick={decoratedOnClick}
                        disabled={!downloadedOrCopied}
                    >Next</button>
                </ButtonDisplay>
            </div>
        </Card.Body>

    }

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={KEY_EXPORT_UI}>
            Secret Key
    </AccordionToggle>
        <Accordion.Collapse eventKey={KEY_EXPORT_UI}>
            {body}
        </Accordion.Collapse>
    </Card>

}
