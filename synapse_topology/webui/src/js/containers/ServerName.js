import { connect } from 'react-redux';

import ServerName from '../components/ServerName';

import { advanceUI, setServername, generateSecretKeys } from '../actions';

const mapStateToProps = (state, ownProps) => ({

});

const mapDispathToProps = (dispatch) => ({
    onClick: servername => {

        dispatch(advanceUI());
        dispatch(setServername(servername));
        dispatch(generateSecretKeys(servername));

    },
});

export default connect(
    null,
    mapDispathToProps,
)(ServerName);