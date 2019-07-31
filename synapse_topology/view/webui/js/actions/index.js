import { ADVANCE_UI, BACK_UI, SET_SERVERNAME } from './types';

export const advance_ui = option => ({
  type: ADVANCE_UI,
  option
});

export const set_servername = servername => ({
  type: SET_SERVERNAME,
  servername
});

export const set_stats = conset => ({
  type: SET_STATS,
  consent
});