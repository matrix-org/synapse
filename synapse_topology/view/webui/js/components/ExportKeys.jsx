import React from 'react';

import ButtonDisplay from './ButtonDisplay';
import ContentWrapper from '../containers/ContentWrapper';
import DownloadOrCopy from './DownloadOrCopy';

import style from '../../less/main.less';


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
      <DownloadOrCopy content={secret_key} fileName="secret_key.txt" />
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