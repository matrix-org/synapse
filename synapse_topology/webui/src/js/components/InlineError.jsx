import React from 'react';

export default ({ error, children }) => {

    return <div
        className="inlineError"
        error={error ? "true" : "false"}>
        {children}
        {error ? <span>{error}</span> : undefined}
    </div>
}