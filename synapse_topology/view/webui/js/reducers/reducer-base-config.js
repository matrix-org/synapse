import { SET_SERVERNAME, SET_STATS } from "../actions/types";

export default (state = { servername: undefined }, action) => {
  switch (action.type) {
    case SET_SERVERNAME:
      return {
        ...state,
        servername: action.servername,
      }
    case SET_STATS:
      return {
        ...state,
        report_stats: action.consent,
      }
    default:
      return state;
  }
};