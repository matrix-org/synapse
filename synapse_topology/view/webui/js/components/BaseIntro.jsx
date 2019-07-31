import React from 'react';

import style from '../../less/main.less';

export default ({ onClick }) =>
  <div className={style.contentWrapper}>
    <h1>Synapse Topology</h1>
    <p>Let's get started.</p>
    <div><button onClick={onClick}>SETUP</button></div>
  </div>