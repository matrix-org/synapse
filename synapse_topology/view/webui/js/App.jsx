import React, { Component } from 'react';

import style from '../less/main.less';
import ActionButton from './ActionButton.jsx';
import Action from './Action.jsx';

export default class App extends Component {
    componentDidMount() {
    }

    render() {
        return <Action>
            <h1>Synapse Topology</h1>
            <p>Let's get started.</p>
            <div><ActionButton text="SETUP"></ActionButton></div>
        </Action>
    }
}