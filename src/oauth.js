const crypto = require('crypto');
const querystring = require('querystring');
const OAuthUtils = require('./_utils');


class OAuth {

    /**
     * Create an OAuth 1.0/A object to perform requests
     * @param {string|null} requestUrl
     * @param {string|null} accessUrl
     * @param {string|null} consumerKey
     * @param {string|null} consumerSecret
     * @param {string|null} version
     * @param {string} authorize_callback
     * @param {string|null} signatureMethod
     * @param {number} nonceSize
     * @param {object|null} customHeaders
     */
    constructor(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback = 'oob', signatureMethod=null, nonceSize = 32, customHeaders=null) {
        this._isEcho = false;
        this._requestUrl = requestUrl;
        this._accessUrl = accessUrl;
        this._consumerKey = consumerKey;
        this._consumerSecret = OAuthUtils.encodeData(consumerSecret);
        if (signatureMethod !== 'PLAINTEXT' && signatureMethod !== 'HMAC-SHA1' && signatureMethod !== 'RSA-SHA1') {
            throw new Error(`Un-supported signature method: ${signatureMethod}`);
        }
        if (signatureMethod === 'RSA-SHA1') {
            this._privateKey = consumerSecret;
        }
        this._version = version;
        this._authorize_callback = authorize_callback;
        this._signatureMethod = signatureMethod;
        this._nonceSize = nonceSize;
        this._headers = customHeaders || {
            Accept : '*/*',
            Connection : 'close',
            'User-Agent' : 'Node authentication'
        };
        this._defaultClientOptions = {
            requestTokenHttpMethod: 'POST',
            accessTokenHttpMethod: 'POST',
            followRedirects: true
        };
        this._clientOptions = this._defaultClientOptions;
        this._oauthParameterSeperator = ',';
    }

    /**
     * Generates a signature
     * @param {string} method
     * @param {string} url
     * @param {string} parameters
     * @param {string} tokenSecret
     * @returns {string}
     * @private
     */
    _getSignature(method, url, parameters, tokenSecret) {
        const signatureBase = OAuthUtils.createSignatureBase(method, url, parameters);
        return this._createSignature(signatureBase, tokenSecret);
    }

    /**
     * Builds the OAuth request authorization header
     * @param {array} orderedParameters
     * @returns {string}
     */
    _buildAuthorizationHeaders(orderedParameters) {
        let authHeader = 'OAuth ';
        if (this._isEcho) {
            authHeader += `realm="${this._realm}",`;
        }
        for (let i = 0; i < orderedParameters.length; i++) {
            // While all the parameters should be included within the signature, only the oauth_ arguments
            // should appear within the authorization header.
            if (OAuthUtils.isParameterNameAnOAuthParameter(orderedParameters[i][0])) {
                authHeader += `${OAuthUtils.encodeData(orderedParameters[i][0])}="${OAuthUtils.encodeData(orderedParameters[i][1])}"${this._oauthParameterSeperator}`;
            }
        }
        authHeader = authHeader.substring(0, authHeader.length - this._oauthParameterSeperator.length);
        return authHeader;
    }

    /**
     * Create a hash signature
     * @param {string} signatureBase
     * @param {string} tokenSecret
     * @returns {string}
     * @private
     */
    _createSignature(signatureBase, tokenSecret) {
        tokenSecret = tokenSecret ? OAuthUtils.encodeData(tokenSecret) : '';
        // consumerSecret is already encoded
        let key = `${this._consumerSecret}&${tokenSecret}`;
        let hash;
        if (this._signatureMethod === 'PLAINTEXT') {
            hash = key;
        }
        else if (this._signatureMethod === 'RSA-SHA1') {
            key = this._privateKey || '';
            hash = crypto.createSign('RSA-SHA1').update(signatureBase).sign(key, 'base64');
        }
        else {
            hash = crypto.createHmac('sha1', key).update(signatureBase).digest('base64');
        }
        return hash;
    }

    /**
     * Returns a options object
     * @param {string} port
     * @param {string} hostname
     * @param {string} method
     * @param {string} path
     * @param {object} headers
     * @returns {{path, headers, method, port, host}}
     * @private
     */
    _createOptions(port, hostname, method, path, headers) {
        return {
            host: hostname,
            port,
            path,
            method,
            headers
        };
    }

    /**
     * Prepares parameters for OAuth request
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @param {string} method
     * @param {string} url
     * @param {object} extra_params
     * @returns {array}
     * @private
     */
    _prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params) {
        const oauthParameters = {
            oauth_timestamp: OAuthUtils.getTimestamp(),
            oauth_nonce: OAuthUtils.getNonce(this._nonceSize),
            oauth_version: this._version,
            oauth_signature_method: this._signatureMethod,
            oauth_consumer_key: this._consumerKey
        };
        if (oauth_token) {
            oauthParameters.oauth_token = oauth_token;
        }
        let sig;
        if (this._isEcho) {
            sig = this._getSignature('GET', this._verifyCredentials,OAuthUtils.normaliseRequestParams(oauthParameters), oauth_token_secret);
        }
        else {
            if (extra_params) {
                for (const key of Object.keys(extra_params)) {
                    oauthParameters[key] = extra_params[key];
                }
            }
            const parsedUrl = new URL(url);
            if (parsedUrl.query) {
                let key2;
                const extraParameters = querystring.parse(parsedUrl.query);
                for (const key of Object.keys(extraParameters)) {
                    const value = extraParameters[key];
                    if (typeof value === 'object'){
                        for (key2 of Object.keys(value)){
                            oauthParameters[`${key}[${key2}]`] = value[key2];
                        }
                    } else {
                        oauthParameters[key] = value;
                    }
                }
            }
            sig = this._getSignature(method, url, OAuthUtils.normaliseRequestParams(oauthParameters), oauth_token_secret);
        }
        const orderedParameters = OAuthUtils.makeArrayOfArgumentsHash(oauthParameters);
        OAuthUtils.sortRequestParams(orderedParameters);
        orderedParameters[orderedParameters.length] = ['oauth_signature', sig];
        return orderedParameters;
    }

    /**
     * Formats a request and sends it to an endpoint
     * @param {string|null} oauth_token
     * @param {string|null} oauth_token_secret
     * @param {string} method
     * @param {string} url
     * @param {object|null} extra_params
     * @param {(string|buffer|null)} post_body
     * @param {(string|null)} post_content_type
     * @returns {{object, object, (string|null)}}
     * @private
     */
    _prepareSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type) {
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);
        if (!post_content_type) {
            post_content_type = 'application/x-www-form-urlencoded';
        }
        const parsedUrl = new URL(url);
        parsedUrl.port = !parsedUrl ? (parsedUrl.protocol === 'http:' ? '80' : '443') : parsedUrl.port;
        const headers = {};
        const authorization = this._buildAuthorizationHeaders(orderedParameters);
        if (this._isEcho) {
            headers['X-Verify-Credentials-Authorization'] = authorization;
        }
        else {
            headers.Authorization = authorization;
        }
        headers.Host = parsedUrl.host
        for (const key of Object.keys(this._headers)) {
            headers[key] = this._headers[key];
        }
        // Filter out any passed extra_params that are really to do with OAuth
        if (extra_params) {
            for (const key of Object.keys(extra_params)) {
                if (OAuthUtils.isParameterNameAnOAuthParameter(key)) {
                    delete extra_params[key];
                }
            }
        }
        if ((method === 'POST' || method === 'PUT')  && (post_body === null && extra_params !== null)) {
            // Fix the mismatch between the output of querystring.stringify() and OAuthUtils.encodeData()
            post_body = querystring.stringify(extra_params)
                .replace(/!/g, '%21')
                .replace(/'/g, '%27')
                .replace(/\(/g, '%28')
                .replace(/\)/g, '%29')
                .replace(/\*/g, '%2A');
        }
        if (post_body) {
            if (Buffer.isBuffer(post_body)) {
                headers['Content-length'] = post_body.length;
            }
            else {
                headers['Content-length'] = Buffer.byteLength(post_body);
            }
        } else {
            headers['Content-length'] = 0;
        }
        headers['Content-Type'] = post_content_type;
        let path;
        if (!parsedUrl.pathname || parsedUrl.pathname === '') {
            parsedUrl.pathname = '/';
        }
        if (parsedUrl.query) {
            path = `${parsedUrl.pathname}?${parsedUrl.query}`;
        }
        else {
            path = parsedUrl.pathname;
        }
        const options = this._createOptions(parsedUrl.port, parsedUrl.hostname, method, path, headers);
        const http_library = OAuthUtils.chooseHttpLibrary(parsedUrl);
        return { http_library, options, post_body }
    }

    /**
     * Sets client options from argument
     * @param {object} options
     */
    setClientOptions(options) {
        let key;
        const mergedOptions = {}
        const { hasOwnProperty } = Object.prototype;
        for (key of Object.keys(this._defaultClientOptions)) {
            if (!hasOwnProperty.call(options, key)) {
                mergedOptions[key] = this._defaultClientOptions[key];
            } else {
                mergedOptions[key] = options[key];
            }
        }
        this._clientOptions = mergedOptions;
    }

    /**
     * Sends an OAuth request with DELETE method
     * @param {string} url
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @returns {Promise<{data: string, response: Object}>}
     */
    delete(url, oauth_token, oauth_token_secret) {
        const { http_library, options, post_body } = this._prepareSecureRequest(oauth_token, oauth_token_secret, 'DELETE', url, null, null, null);
        return OAuthUtils.executeRequest(http_library, options, post_body);
    }

    /**
     * Sends an OAuth request with GET method
     * @param {string} url
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @returns {Promise<{data: string, response: Object}>}
     */
    get(url, oauth_token, oauth_token_secret) {
        const { http_library, options, post_body } = this._prepareSecureRequest(oauth_token, oauth_token_secret, 'GET', url, null, null, null);
        return OAuthUtils.executeRequest(http_library, options, post_body);
    }

    /**
     * Sends an OAuth request with PUT method
     * @param url
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @param {(string|object)} post_body
     * @param {(string|null)} post_content_type
     * @returns {Promise<{data: string, response: Object}>}
     */
    async put(url, oauth_token, oauth_token_secret, post_body, post_content_type=null) {
        return this._putOrPost('PUT', url, oauth_token, oauth_token_secret, post_body, post_content_type);
    }

    /**
     * Sends an OAuth request with POST method
     * @param {string} url
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @param {(string|object)} post_body
     * @param {(string|null)} post_content_type
     * @returns {Promise<{data: string, response: Object}>}
     */
    async post(url, oauth_token, oauth_token_secret, post_body, post_content_type=null) {
        return this._putOrPost('POST', url, oauth_token, oauth_token_secret, post_body, post_content_type);
    }

    /**
     * Sends a PUT or POST request depending on the method
     * @param {('PUT'|'POST')} method
     * @param {string} url
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @param {(string|object)} post_body
     * @param {(string|null)} post_content_type
     * @returns {Promise<{data: string, response: Object}>}
     * @private
     */
    _putOrPost(method, url, oauth_token, oauth_token_secret, post_body, post_content_type) {
        let extra_params = null;
        if (typeof post_content_type === 'function') {
            post_content_type = null;
        }
        if (typeof post_body !== 'string' && !Buffer.isBuffer(post_body)) {
            post_content_type = 'application/x-www-form-urlencoded';
            extra_params = post_body;
            post_body = null;
        }
        const prepared = this._prepareSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type);
        const { http_library, options } = prepared;
        return OAuthUtils.executeRequest(http_library, options, prepared.post_body);
    }

    /**
     * Gets a request token from the OAuth provider and passes that information back
     * to the calling code.
     *
     * The callback should expect a function of the following form:
     *
     * function(err, token, token_secret, parsedQueryString) {}
     *
     * This method has optional parameters so can be called in the following 2 ways:
     *
     * 1) Primary use case: Does a basic request with no extra parameters
     *  getOAuthRequestToken( callbackFunction )
     *
     * 2) As above but allows for provision of extra parameters to be sent as part of the query to the server.
     *  getOAuthRequestToken( extraParams, callbackFunction )
     *
     * N.B. This method will HTTP POST verbs by default, if you wish to override this behaviour you will
     * need to provide a requestTokenHttpMethod option when creating the client.
     * @param {(function|object)} extraParams
     * @returns {Promise<{oauth_token: string | string[], response: Object, oauth_token_secret: string | string[], results: ParsedUrlQuery}>}
     */
    async getOAuthRequestToken(extraParams) {
        if (typeof extraParams === 'function'){
            extraParams = {};
        }
        // Callbacks are 1.0A related
        if (this._authorize_callback) {
            extraParams.oauth_callback = this._authorize_callback;
        }
        const { http_library, options, post_body } = this._prepareSecureRequest(null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null);
        const { data, response } = OAuthUtils.executeRequest(http_library, options, post_body);
        const results = querystring.parse(data);
        const {oauth_token} = results;
        const {oauth_token_secret} = results;
        delete results.oauth_token;
        delete results.oauth_token_secret;
        return { oauth_token, oauth_token_secret, results, response };
    }

    /**
     * Gets an OAuth access token and returns a object containing the results
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @param {string} oauth_verifier
     * @returns {Promise<{response: Object, oauth_access_token_secret: string | string[], oauth_access_token: string | string[], results: ParsedUrlQuery}>}
     */
    async getOAuthAccessToken(oauth_token, oauth_token_secret, oauth_verifier) {
        const extraParams = {
            oauth_verifier,
        };
        const { http_library, options, post_body } = this._prepareSecureRequest(oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null);
        const { data, response } = await OAuthUtils.executeRequest(http_library, options, post_body);
        const results = querystring.parse(data);
        const oauth_access_token = results.oauth_token;
        delete results.oauth_token;
        const oauth_access_token_secret = results.oauth_token_secret;
        delete results.oauth_token_secret;
        return { oauth_access_token, oauth_access_token_secret, results, response };
    }

    /**
     * Generates a signed URL string
     * @param {string} url
     * @param {string|null} oauth_token
     * @param {string|null} oauth_token_secret
     * @param {string|null} method
     * @returns {string}
     */
    signUrl(url, oauth_token=null, oauth_token_secret=null, method=null) {
        method = method ? method : 'GET';
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        const parsedUrl = URL.parse(url, false);
        let query = '';
        for (let i = 0; i < orderedParameters.length; i++) {
            query += `${orderedParameters[i][0]}=${OAuthUtils.encodeData(orderedParameters[i][1])}&`;
        }
        query = query.substring(0, query.length-1);
        return `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}?${query}`;
    }

    /**
     * Returns the auth header string
     * @param {string} url
     * @param {string} oauth_token
     * @param {string} oauth_token_secret
     * @param {string|null} method
     * @returns {string}
     */
    authHeader(url, oauth_token, oauth_token_secret, method=null) {
        method = method ? method : 'GET';
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        return this._buildAuthorizationHeaders(orderedParameters);
    }

}

module.exports = OAuth;