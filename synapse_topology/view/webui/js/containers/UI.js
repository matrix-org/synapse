import { connect } from 'react-redux';
import UI from '../components/UI';

const mapStateToProps = ({ setup_done, setup_ui, config_ui }) => ({
  setup_done,
  setup_ui,
  config_ui,
})


const mapDispathToProps = (dispatch, ownProps) => ({

})

export default connect(
  mapStateToProps,
)(UI)