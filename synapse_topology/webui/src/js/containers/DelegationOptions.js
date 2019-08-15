import { connect } from 'react-redux';

import DelegationOptions from '../components/DelegationOptions';

import {
    setDelegation,
    advanceUI,
    setDelegationServername,
    setDelegationPorts,
} from '../actions';

import { DELEGATION_TYPES } from '../actions/constants';

const mapStateToProps = (state, { children }) => {

    return {
        servername: state.baseConfig.servername,
    }

}


const mapDispatchToProps = (dispatch) => ({
    onClick: (type, servername, fedPort, clientPort) => {

        dispatch(advanceUI());
        dispatch(setDelegation(type));
        dispatch(setDelegationServername(servername));
        dispatch(setDelegationPorts(fedPort, clientPort));

    },

    skip: () => {

        dispatch(advanceUI());
        dispatch(setDelegation(DELEGATION_TYPES.LOCAL));

    },
});

export default connect(
    mapStateToProps,
    mapDispatchToProps,
)(DelegationOptions);