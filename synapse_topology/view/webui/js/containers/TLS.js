import { connect } from 'react-redux';

import TLS from '../components/TLS';

import { advance_ui, set_tls } from '../actions';

import { TLS_TYPES } from '../actions/constants';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
  onClickACME: () => {
    dispatch(advance_ui(TLS_TYPES.ACME));
    dispatch(set_tls(TLS_TYPES.ACME));
  },
  onClickTLS: () => {
    dispatch(advance_ui(TLS_TYPES.TLS));
    dispatch(set_tls(TLS_TYPES.TLS));
  },
  onClickReverseProxy: () => {
    dispatch(advance_ui(TLS_TYPES.REVERSE_PROXY)),
      dispatch(set_tls(TLS_TYPES.REVERSE_PROXY))
  },
});

export default connect(
  null,
  mapDispathToProps
)(TLS)