const http = require('http');
const https = require('https');

/**
 * Returns true if this is a host that closes *before* it ends
 * @param {string} hostName
 * @returns {boolean}
 */
module.exports.isAnEarlyCloseHost = function (hostName) {
    return hostName && (hostName.match(/.*google(apis)?.com$/))?.length > 0;
};

/**
 * Adds all the key/value pairs of the 'from' object to the 'to' object
 * @param {object} from
 * @param {object} to
 */
module.exports.combineObjects = function (from, to) {
    let i = 0;
    const keys = Object.keys(from);
    const len = keys.length;
    for (i; i < len; i++) {
        to[keys[i]] = from[keys[i]];
    }
};

/**
 * Encode special characters
 * @param {(string|null)} toEncode
 * @returns {string}
 */
module.exports.encodeData = function (toEncode) {
    if (toEncode === null || toEncode === '') {
        return '';
    }
    const result = encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth's RFC3986's and Javascript's beliefs in what is right and wrong ;)
    return result.replace(/!/g, '%21')
        .replace(/'/g, '%27')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29')
        .replace(/\*/g, '%2A');
}

/**
 * Decode special characters
 * @param {(string|null)} toDecode
 * @returns {string}
 */
module.exports.decodeData = function (toDecode) {
    if (toDecode !== null) {
        toDecode = toDecode.replace(/\+/g, ' ');
    }
    return decodeURIComponent(toDecode);
}

/**
 * Returns a normalized URL using parsed URL components
 * @param {string} url
 * @returns {string}
 */
module.exports.normalizeUrl = function (url) {
    const parsedUrl = new URL(url);
    let port = '';
    if (parsedUrl.port) {
        if ((parsedUrl.protocol === 'http:' && parsedUrl.port !== '80' ) ||
            (parsedUrl.protocol === 'https:' && parsedUrl.port !== '443')) {
            port = `:${parsedUrl.port}`;
        }
    }
    if (!parsedUrl.pathname || parsedUrl.pathname === '') {
        parsedUrl.pathname = '/';
    }
    return `${parsedUrl.protocol}//${parsedUrl.hostname}${port}${parsedUrl.pathname}`;
}

/**
 * Creates a string signature base
 * @param {string} method
 * @param {string} url
 * @param {string} parameters
 * @returns {string}
 */
module.exports.createSignatureBase = function (method, url, parameters) {
    url = this.encodeData(this.normalizeUrl(url));
    parameters = this.encodeData(parameters);
    return `${method.toUpperCase()}&${url}&${parameters}`;
}

/**
 * Determines whether a parameter is considered an OAuth parameter
 * @param {string} parameter
 * @returns {boolean}
 */
module.exports.isParameterNameAnOAuthParameter = function (parameter) {
    const m = parameter.match('^oauth_');
    return !!(m && (m[0] === 'oauth_'));
}

/**
 * Takes an object literal that represents the arguments, and returns an array
 * of argument/value pairs.
 * @param {object} argumentsHash
 * @returns {[]}
 */
module.exports.makeArrayOfArgumentsHash = function (argumentsHash) {
    const argument_pairs = [];
    for (const key of Object.keys(argumentsHash)) {
        const value = argumentsHash[key];
        if (Array.isArray(value)) {
            for (let i = 0; i < value.length; i++) {
                argument_pairs[argument_pairs.length] = [key, value[i]];
            }
        }
        else {
            argument_pairs[argument_pairs.length] = [key, value];
        }
    }
    return argument_pairs;
}

/**
 * Sorts the encoded key value pairs by encoded name, then encoded value
 * @param {array} argument_pairs
 */
module.exports.sortRequestParams = function (argument_pairs) {
    // Sort by name, then value.
    argument_pairs.sort((a, b) => {
        if (a[0] === b[0])  {
            return a[1] < b[1] ? -1 : 1;
        }
        return a[0] < b[0] ? -1 : 1;
    });
}

/**
 * Normalizes args to request parameter format
 * @param {object} args
 * @returns {string}
 */
module.exports.normaliseRequestParams = function (args) {
    const argument_pairs = this.makeArrayOfArgumentsHash(args);
    // First encode them #3.4.1.3.2 .1
    for (let i = 0; i < argument_pairs.length; i++) {
        argument_pairs[i][0] = this.encodeData(argument_pairs[i][0]);
        argument_pairs[i][1] = this.encodeData(argument_pairs[i][1]);
    }
    // Then sort them #3.4.1.3.2 .2
    this.sortRequestParams(argument_pairs);
    // Then concatenate together #3.4.1.3.2 .3 & .4
    let newArgs = '';
    for (let i = 0; i < argument_pairs.length; i++) {
        newArgs += argument_pairs[i][0];
        newArgs += '='
        newArgs += argument_pairs[i][1];
        if (i < argument_pairs.length-1) {
            newArgs += '&';
        }
    }
    return newArgs;
}

/**
 * A list of NONCE characters
 * @type {string[]}
 */
module.exports.NONCE_CHARS = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
    'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
    'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
    '4','5','6','7','8','9'];

/**
 * Gets a string-joined list of NONCE characters based on the nonce size
 * @param {number} nonceSize
 * @returns {string}
 */
module.exports.getNonce = function (nonceSize) {
    const result = [];
    const chars = this.NONCE_CHARS;
    let char_pos;
    const nonce_chars_length = chars.length;
    for (let i = 0; i < nonceSize; i++) {
        char_pos = Math.floor(Math.random() * nonce_chars_length);
        result[i] = chars[char_pos];
    }
    return result.join('');
}

/**
 * Checks if the status code is in the 200s
 * @param {object} response
 * @returns {boolean}
 */
module.exports.responseIsOkay = function (response) {
    return response.statusCode >= 200 && response.statusCode <= 299;
}

/**
 * Checks if the status code is in the 300s
 * @param {object} response
 * @param {object} clientOptions
 * @returns {boolean}
 */
module.exports.responseIsRedirect = function (response, clientOptions) {
    return (response.statusCode === 301 || response.statusCode === 302) && clientOptions.followRedirects && response.headers && response.headers?.location;
}

/**
 * Gets a timestamp in seconds
 * @returns {number}
 */
module.exports.getTimestamp = function () {
    return Math.floor((new Date()).getTime() / 1000);
}

/**
 * Returns the correct http/s library for the protocol
 * @param {URL} parsedUrl
 * @returns {module:https|module:http}
 */
module.exports.chooseHttpLibrary = function (parsedUrl) {
    return parsedUrl.protocol === 'https:' ? https : http;
}

/**
 * Performs the http/s oauth request
 * @param {(http|https)} http_library
 * @param {object} options
 * @param {*} post_body
 * @returns {Promise<{data: string, response: object}>}
 * @private
 */
module.exports.executeRequest = function (http_library, options, post_body) {
    return new Promise((resolve, reject) => {
        // Some hosts *cough* google appear to close the connection early / send no content-length header
        // allow this behaviour.
        const isEarlyClose = this.isAnEarlyCloseHost(options.host);
        /**
         * Handles the response from http/s request
         * @param {object} response
         * @param {string} data
         */
        const responseHandler = (response, data) => {
            if (!(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode !== 301) && (response.statusCode !== 302)) {
                return reject({statusCode: response.statusCode, data, response});
            }
            return resolve({data, response});

        }
        let data = '';
        const request = http_library.request(options, (response) => {
            response.on('data', (chunk) => {
                data += chunk;
            });
            response.on('end', () => {
                responseHandler(response, data);
            });
            response.on('close', () => {
                if (isEarlyClose) {
                    responseHandler(response, data);
                }
            });
        });
        request.on('error', (e) => {
            return reject(e);
        });
        if ((options.method === 'POST' || options.method === 'PUT') && post_body) {
            request.write(post_body);
        }
        request.end();
    });
}