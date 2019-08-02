import React from 'react';

import style from '../../less/main.less';

export default ({ servername, children }) => {
  if (servername) {
    return <div>
      <p className={style.servername}>{servername}</p>
      <div className={style.contentWrapper}>
        {children}
      </div>
    </div>
  } else {
    return <div className={style.contentWrapper}>{children}</div>
  }
}