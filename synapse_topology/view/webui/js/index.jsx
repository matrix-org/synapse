import React from 'react';
import { render } from 'react-dom';
import { Provider } from 'react-redux';
import { createStore, applyMiddleware } from 'redux'
import thunk from 'redux-thunk';
import rootReducer from './reducers';
import UI from './containers/UI';
import style from '../less/main.less';
import logo from '../fonts/matrix-logo.svg';

import { startup } from './actions';

const store = createStore(
  rootReducer,
  applyMiddleware(thunk),
  //+  window.__REDUX_DEVTOOLS_EXTENSION__ && window.__REDUX_DEVTOOLS_EXTENSION__()
);

store.dispatch(startup());

render(
  <Provider store={store}>
    {/* <img className={style.logo} src={logo} /> */}
    <UI />
  </Provider>,
  document.getElementById("content")
);