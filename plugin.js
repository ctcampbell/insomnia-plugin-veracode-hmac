const path = require('path');
const os = require('os');
const configparser = require('configparser');
const hmac = require('./veracode-hmac.js');

const hosts = ['api.veracode.com', 'analysiscenter.veracode.com', 'api.veracode.io', 'api.sourceclear.io', 'api.sourceclear.com', 'api.veracode.eu', 'analysiscenter.veracode.eu', 'api.sourceclear.eu', 'api.veracode.us','analysiscenter.veracode.us'];

// Request hook to set header on every request
module.exports.requestHooks = [
    context => {
        let url = new URL(context.request.getUrl());
        let params = context.request.getParameters();
        
        if (url.protocol === 'https:' && hosts.includes(url.hostname)) {
            let authProfile = context.request.getEnvironmentVariable('veracode_auth_profile');
            if (!authProfile) {
                authProfile = 'default';
            }
            let veracodeCredsFile = path.join(os.homedir(), '.veracode', 'credentials');
            let config = new configparser();
            config.read(veracodeCredsFile);
            let id = config.get(authProfile, 'veracode_api_key_id');
            let key = config.get(authProfile, 'veracode_api_key_secret');
            if (id[8] === '-' && key[8] === '-') {
                id = id.substring(9);
                key = key.substring(9);
            }

            let paramStringInitialValue = url.search === '' ? '?' : url.search + '&';
            let paramsString = params.reduce((accum, item, index, arr) => {
                if (item.name === '') {
                    return accum;
                } else if (item.value === '') {
                    return `${accum}${item.name}&`
                } else {
                    return `${accum}${item.name}=${item.value}&`
                }
            }, paramStringInitialValue);
            paramsString = paramsString.slice(0, -1);

            let header = hmac.calculateAuthorizationHeader(id, key, url.hostname, url.pathname, paramsString, context.request.getMethod());
            context.request.setHeader('Authorization', header);
        }

    }
];