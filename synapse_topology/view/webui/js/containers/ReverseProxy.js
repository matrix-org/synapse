import { connect } from 'react-redux';

import ReverseProxy from '../components/ReverseProxy';

import { advance_ui, set_reverse_proxy } from '../actions';

const mapStateToProps = (state, ownProps) => {

};

const mapDispatchToProps = (dispatch) => ({
  onClick: proxy_type => {
    dispatch(set_reverse_proxy(proxy_type));
    dispatch(advance_ui());
  }
});

export default connect(
  null,
  mapDispatchToProps
)(ReverseProxy);