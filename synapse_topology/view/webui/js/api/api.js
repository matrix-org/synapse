import fetchAbsolute from 'fetch-absolute';
import {
    API_URL,
    SERVER_NAME,
    SECRET_KEY,
    CONFIG,
    CONFIG_SOMETHING,
} from './constants';

const fetchAbs = fetchAbsolute(fetch)(API_URL)

const get_server_name = () => {
    fetchAbs(SERVER_NAME)
        .then(res => res.json())
};

const post_server_name = () => {

};

const get_secret_key = () => {
    fetchAbs(SECRET_KEY)
        .then(res => res.json())

};

const get_config = () => {

};

const post_config = () => {

};

export {
    get_server_name,
    post_server_name,
    get_secret_key,
    get_config,
    post_config,
}