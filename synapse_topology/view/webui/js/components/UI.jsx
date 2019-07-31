import React from 'react';

import style from '../../less/main.less';

import IntroUi from '../containers/BaseIntro';
import ServerName from '../containers/ServerName';

import {
  BASE_INTRO_UI,
  SERVER_NAME_UI,
  STATS_REPORT_UI,
  KEY_EXPORT_UI,
  DELEGATION_OPTIONS_UI,
  WELL_KNOWN_UI,
  DNS_UI,
  WORKER_UI,
  ACME_UI,
  REVERSE_PROXY_UI,
  PORT_SELECTION_UI,
  REVERSE_PROXY_TEMPLATE_UI
} from '../reducers/reducer-base-config-ui';
import StatsReporter from '../containers/StatsReporter';

export default ({ active_ui, dispatch }) => {
  switch (active_ui) {
    case BASE_INTRO_UI:
      return < IntroUi />
    case SERVER_NAME_UI:
      return <ServerName />
    case STATS_REPORT_UI:
      return <StatsReporter />
    case KEY_EXPORT_UI:
    case DELEGATION_OPTIONS_UI:
    case WELL_KNOWN_UI:
    case DNS_UI:
    case WORKER_UI:
    case ACME_UI:
    case REVERSE_PROXY_UI:
    case PORT_SELECTION_UI:
    case REVERSE_PROXY_TEMPLATE_UI:
    default:
      return <h1>how did i get here?</h1>
  }
}