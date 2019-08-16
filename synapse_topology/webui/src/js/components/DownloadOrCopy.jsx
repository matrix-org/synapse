import React from 'react';
import ButtonDisplay from './ButtonDisplay';

const download = (filename, text) => {

    const e = document.createElement('a');
    e.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    e.setAttribute('download', filename);

    e.style.display = 'none';
    document.body.appendChild(e);

    e.click();

    document.body.removeChild(e);

}

export default ({ content, fileName }) =>
    <ButtonDisplay>
        <div className='buttonGroup'>
            <button onClick={() => download(fileName, content)}>Download</button>
            <span className='or'>or</span>
            <button onClick={() => navigator.clipboard.writeText(content)}>Copy</button>
        </div>
    </ButtonDisplay>
