/* eslint-disable max-len */
import React, { useState } from 'react';

import style from '../../scss/main.scss';

import Accordion from 'react-bootstrap/Accordion';
import Card from 'react-bootstrap/Card';
import Tabs from 'react-bootstrap/Tabs';
import Tab from 'react-bootstrap/Tab';
import useAccordionToggle from 'react-bootstrap/useAccordionToggle';

import { TLS_UI } from '../reducers/ui-constants';
import { TLS_TYPES, REVERSE_PROXY_TYPES } from '../actions/constants';
import AccordionToggle from '../containers/AccordionToggle';
import { nextUI } from '../reducers/setup-ui-reducer';

const tlsLink = "https://en.wikipedia.org/wiki/Transport_Layer_Security";
const apacheLink = "http://httpd.apache.org/";
const caddyLink = "https://caddyserver.com/";
const haproxyLink = "http://www.haproxy.org/";
const nginxLink = "https://www.nginx.com/";

export default ({
    testingCertPaths,
    uploadingCerts,
    certPathInvalid,
    certKeyPathInvalid,
    onClickCertPath,
    onClickCertUpload,
    onClickACME,
    onClickReverseProxy,
}) => {

    const defaultType = TLS_TYPES.REVERSE_PROXY;

    const [type, setType] = useState(defaultType);

    const [certPath, setCertPath] = useState("");
    const [certKeyPath, setCertKeyPath] = useState("");
    const [certFile, setCertFile] = useState();
    const [certKeyFile, setCertKeyFile] = useState();

    const defaultValue = REVERSE_PROXY_TYPES.NGINX;
    const [reverseProxy, setReverseProxy] = useState(defaultValue);

    const toggle = useAccordionToggle(nextUI(TLS_UI));

    return <Card>
        <AccordionToggle as={Card.Header} eventKey={TLS_UI}>
            TLS
        </AccordionToggle>
        <Accordion.Collapse eventKey={TLS_UI}>
            <Card.Body>
                <p>
                    Synapse uses TLS to ensure communication between homeservers is
                    secure. To use TLS, you’ll need a TLS certificate. Synapse supports
                    ACME, providing your own certificates, or reverse proxy handling TLS
                    certificates.
                </p>
                <Tabs defaultActiveKey={defaultType} onSelect={k => setType(k)}>
                    <Tab eventKey={TLS_TYPES.REVERSE_PROXY} title="Reverse Proxy">
                        <p>
                            It is recommended to run Synapse behind a reverse proxy such
                            as <a target="_blank" href={apacheLink}>Apache</a>, <a target="_blank" href={caddyLink}>Caddy</a>, <a target="_blank" href={haproxyLink}>HAProxy</a>, or <a target="_blank" href={nginxLink}>NGiNX</a>.
                        </p>
                        <p>
                            The main benefit to this is that the reverse proxy can listen on
                            the privileged port 443 (which clients like Riot expect to connect
                            to) on behalf of synapse. The incoming traffic is then forwarded
                            to Synapse on a non privileged port.
                        </p>
                        <p>
                            You need root to listen on ports 0 to 1024 inclusive and running
                            synapse with root privileges is <b>strongly discouraged</b>.
                                                                                                                    Reverse proxies are more secure, run with root and pass things on
                                                                                                                    like nobody's business.
                        </p>
                        <p>
                            (Note: you can also have synapse use a non privileged port by
                            using one of the delegation methods mentioned earlier.)
                        </p>
                        <p>
                            If you choose to use a Reverse Proxy we'll provide you with
                            configuration templates later.
                        </p>
                        <p>More information about Reverse Proxies
                            <a href="https://github.com/matrix-org/synapse/blob/master/docs/reverse_proxy.rst">
                                in the docs</a>.
                        </p>
                        <p>
                            Please choose the reverse proxy you're using. This is just so we can provide
                            you with a template later, if you already know how you're going to set yours
                            up don't worry too much about this.
                        </p>
                        <select defaultValue={defaultValue} onChange={e => setReverseProxy(e.target.value)} >
                            <option value={REVERSE_PROXY_TYPES.APACHE}>Apache</option>
                            <option value={REVERSE_PROXY_TYPES.CADDY}>Caddy</option>
                            <option value={REVERSE_PROXY_TYPES.HAPROXY}>HAProxy</option>
                            <option value={REVERSE_PROXY_TYPES.NGINX}>NGiNX</option>
                            <option value={REVERSE_PROXY_TYPES.OTHER}>Some other Reverse Proxy</option>
                        </select>
                        <div>
                            <button onClick={() => {

                                toggle();
                                onClickReverseProxy(reverseProxy)

                            }}>
                                Use a reverse proxy with TLS
                        </button>
                        </div>
                    </Tab>
                    <Tab eventKey={TLS_TYPES.ACME} title="ACME">
                        <p>
                            ACME is a protocol that allows TLS certificates to be requested
                            automagically. Synapse supports ACME by requesting certs from
                            Let's Encrypt, which is one of the easiest ways to manage your
                            certificates.
                        </p>
                        <p>
                            If you wish to use ACME you will need access to port 80 which
                            usually requires root privileges. Do not run Synapse as root. Use
                            a Reverse Proxy or Authbind
                        </p>
                        <button onClick={() => {

                            toggle();
                            onClickACME()

                        }}>Use ACME</button>
                    </Tab>
                    <Tab eventKey={TLS_TYPES.TLS} title="Provide your own TLS certs">
                        <p>
                            Specify a path to or upload TLS certs for the domain.
                        </p>
                        <p>Please enter {certPathInvalid ? "a valid" : "the"} path to the cert</p>
                        <input
                            className={certPathInvalid ? style.invalidInput : undefined}
                            type="text"
                            placeholder="/path/to/your/cert.pem"
                            value={certPath ? certPath : undefined}
                            onChange={e => setCertPath(e.target.value)}
                        />

                        <p>Please enter {certKeyPathInvalid ? "a valid" : "the"} path to the cert's key</p>
                        <input
                            className={certKeyPathInvalid ? style.invalidInput : undefined}
                            type="text"
                            placeholder="/path/to/your/cert/key.tls.key"
                            value={certKeyPath ? certKeyPath : undefined}
                            onChange={e => setCertKeyPath(e.target.value)}
                        />

                        <button
                            disabled={certPath && certKeyPath ? undefined : true}
                            onClick={() => onClickCertPath(certPath, certKeyPath, toggle)}
                        >Use TLS Path</button>

                        <h3>OR..</h3>
                        <h1>Upload a TLS cert</h1>
                        <p>Upload a cert file.</p>
                        <input type="file" name="cert" onChange={e => setCertFile(e.target.files[0])} />
                        <p>Upload the cert's private key file.</p>
                        <input type="file" name="certkey" onChange={e => setCertKeyFile(e.target.files[0])} />
                        <button disabled={certFile && certKeyFile ? undefined : true} onClick={() => onClickCertUpload(certFile, certKeyFile, toggle)}>Upload cert</button>
                    </Tab>
                </Tabs>
            </Card.Body>
        </Accordion.Collapse>
    </Card>

}