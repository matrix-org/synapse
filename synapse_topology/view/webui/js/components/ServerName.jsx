import React, { useState } from 'react';

import style from '../../less/main.less';

export default ({ onClick }) => {
  const [servername, setServerName] = useState("");

  const onChange = event => {
    setServerName(event.target.value);
  }

  return <div className={style.contentWrapper}>
    <h1>Select a server name</h1>
    <p>This is very important. More information here.</p>
    <input type="text" onChange={onChange} autoFocus placeholder="synapse.dev"></input>
    <div>
      <button disabled={servername ? undefined : true} onClick={() => onClick()}>I like it</button>
    </div>
  </div >;
}