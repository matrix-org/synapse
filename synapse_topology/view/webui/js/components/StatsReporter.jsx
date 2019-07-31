import React from 'react';

import style from '../../less/main.less';

import ButtonDisplay from './ButtonDisplay';


export default ({ onClick }) =>
  <div className={style.contentWrapper}>
    <h1>Anonymous Statistics</h1>
    <p>Would you like to report anonymouse statistics to matrix.org?</p>
    <ButtonDisplay>
      <button onClick={() => onClick(true)}>YES</button>
      <button onClick={() => onClick(false)} className={style.redButton}>NO</button>
    </ButtonDisplay>
  </div >