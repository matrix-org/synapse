import { connect } from 'react-redux';
import UI from '../components/UI';

const mapStateToProps = ({ setup_done, setup_ui, config_ui, base_config }) => ({
  setup_done,
  setup_ui,
  config_ui,
  base_config,
})


const mapDispathToProps = (dispatch, ownProps) => ({

})

export default connect(
  mapStateToProps,
)(UI)