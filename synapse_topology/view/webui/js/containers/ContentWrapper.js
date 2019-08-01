import { connect } from 'react-redux';

import ContentWrapper from '../components/ContentWrapper';

const mapStateToProps = (state, { children }) => {
  const servername = state.base_config.servername;
  console.log(state)
  return {
    servername,
    children,
  }
}


const mapDispatchToProps = (dispatch) => ({
});

export default connect(
  mapStateToProps
)(ContentWrapper);