import React from 'react';

import ButtonDisplay from './ButtonDisplay';
import ContentWrapper from '../containers/ContentWrapper';

import style from '../../less/main.less';

const download = (filename, text) => {
  const e = document.createElement('a');
  e.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
  e.setAttribute('download', filename);

  e.style.display = 'none';
  document.body.appendChild(e);

  e.click();

  document.body.removeChild(e);
}

export default ({ secret_key_loaded, secret_key, onClick }) => {
  if (!secret_key_loaded) {
    return <ContentWrapper>
      <h1>Generating secret key</h1>
    </ContentWrapper>;
  } else {
    return <ContentWrapper>
      <h1>Export keys</h1>
      <p>
        This is your server's secret key:
      </p>
      <p className={style.keyDisplay}>{secret_key}</p>
      <ButtonDisplay>
        <button onClick={() => download("secret_key.txt", secret_key)}>Download</button>
        <button onClick={() => navigator.clipboard.writeText(secret_key)}>Copy</button>
      </ButtonDisplay>
      <p>
        The server uses this to identify
        itself to other servers. You can use it to retain ownership of the server's
        name in the event that the server itself becomes irrevocably inaccessible.
      </p>
      <p>Keep it safe</p>
      <ButtonDisplay><button onClick={onClick}>Continue</button></ButtonDisplay>
    </ContentWrapper>;
  }
}