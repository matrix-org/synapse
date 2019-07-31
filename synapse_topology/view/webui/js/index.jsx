import React from 'react';
import { render } from 'react-dom';
import { Provider } from 'react-redux';
import { createStore } from 'redux'
import rootReducer from './reducers';
import UI from './containers/UI';

const store = createStore(
  rootReducer,/* preloadedState, */
  +  window.__REDUX_DEVTOOLS_EXTENSION__ && window.__REDUX_DEVTOOLS_EXTENSION__()
);

render(
  <Provider store={store}>
    <UI />
  </Provider>,
  document.getElementById("content")
);