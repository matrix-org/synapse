import React from 'react';

import style from '../../less/main.less';

export default (props) => {
  console.log("props")
  console.log(props)
  console.log("props")

  const { servername, children } = props
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