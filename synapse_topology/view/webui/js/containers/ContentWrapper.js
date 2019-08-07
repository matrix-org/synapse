import { connect } from 'react-redux';

import ContentWrapper from '../components/ContentWrapper';

const mapStateToProps = (state, { children }) => ({
  servername: state.base_config.servername,
  children,
})


const mapDispatchToProps = (dispatch) => ({
});

export default connect(
  mapStateToProps
)(ContentWrapper);