import { connect } from 'react-redux';
import UI from '../components/UI';

const mapStateToProps = ({ ui }, ownProps) => ({
  active_ui: ui.active_ui,
  ...ownProps,
})


const mapDispathToProps = (dispatch, ownProps) => ({

})

export default connect(
  mapStateToProps,
)(UI)