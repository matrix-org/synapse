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

export default ({ content, fileName, onClick = () => undefined }) => {

    const downloadOnClick = () => {

        download(fileName, content);
        onClick();

    }

    const copyOnClick = () => {

        navigator.clipboard.writeText(content);
        onClick();

    }

    return <ButtonDisplay>
        <div className='buttonGroup'>
            <button onClick={downloadOnClick}>Download</button>
            <span className='or'>or</span>
            <button onClick={copyOnClick}>Copy</button>
        </div>
    </ButtonDisplay>

}
