import { connect } from 'react-redux';

import ServerName from '../components/ServerName';

import { advanceUI, setServername } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
    onClick: servername => {

        dispatch(advanceUI());
        dispatch(setServername(servername));

    },
});

export default connect(
    null,
    mapDispathToProps,
)(ServerName);