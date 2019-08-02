import React, { useState } from 'react';

import style from '../../less/main.less';

import ButtonDisplay from './ButtonDisplay';
import ContentWrapper from '../containers/ContentWrapper';


export default ({ testingCertPaths, uploadingCerts, certPathInvalid, certKeyPathInvalid, onClickCertPath, onClickCertUpload }) => {
  const [certPath, setCertPath] = useState("");
  const [certKeyPath, setCertKeyPath] = useState("");
  const [certFile, setCertFile] = useState();
  const [certKeyFile, setCertKeyFile] = useState();

  if (testingCertPaths) {
    return <ContentWrapper><h1>Testing the cert paths.</h1></ContentWrapper>
  } else if (uploadingCerts) {
    return <ContentWrapper><h1>Uploading Certs</h1></ContentWrapper>
  } else {
    return <ContentWrapper>
      <h1>TLS Path</h1>
      <p>
        If you have a tls cert on your server you can provide a path to it here.
        The cert needs to be a `.pem` file that includes the
        full certificate chain including any intermediate certificates.
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
        onClick={() => onClickCertPath(certPath, certKeyPath)}
      >Use TLS Path</button>

      <h3>OR..</h3>
      <h1>Upload a TLS cert</h1>
      <p>Upload a cert file.</p>
      <input type="file" name="cert" onChange={e => setCertFile(e.target.files[0])} />
      <p>Upload the cert's private key file.</p>
      <input type="file" name="certkey" onChange={e => setCertKeyFile(e.target.files[0])} />
      <button disabled={certFile && certKeyFile ? undefined : true} onClick={() => onClickCertUpload(certFile, certKeyFile)}>Upload cert</button>

    </ContentWrapper >
  }
}