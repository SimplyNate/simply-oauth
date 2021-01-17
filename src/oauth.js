const crypto = require('crypto');
const sha1 = require('./sha1');
const http = require('http');
const https = require('https');
// const URL = require('url');
const querystring = require('querystring');
const OAuthUtils = require('./_utils');


class OAuth {

    /**
     * Create an OAuth 1.0/A object to perform requests
     * @param {string} requestUrl
     * @param {string} accessUrl
     * @param {string} consumerKey
     * @param {string} consumerSecret
     * @param {string} version
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

    _getSignature(method, url, parameters, tokenSecret) {
        const signatureBase = OAuthUtils.createSignatureBase(method, url, parameters);
        return this._createSignature(signatureBase, tokenSecret);
    }

    // build the OAuth request authorization header
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

    _createSignature(signatureBase, tokenSecret) {
        tokenSecret = tokenSecret === undefined ? '' : OAuthUtils.encodeData(tokenSecret);
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
            if (crypto.Hmac) {
                hash = crypto.createHmac('sha1', key).update(signatureBase).digest('base64');
            }
            else {
                hash = sha1.HMACSHA1(key, signatureBase);
            }
        }
        return hash;
    }

    _createClient(port, hostname, method, path, headers, sslEnabled) {
        const options = {
            host: hostname,
            port,
            path,
            method,
            headers
        };
        let httpModel;
        if (sslEnabled) {
            httpModel = https;
        }
        else {
            httpModel = http;
        }
        return httpModel.request(options);
    }

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
                        oauthParameters[key]= value;
                    }
                }
            }
            sig = this._getSignature(method, url, OAuthUtils.normaliseRequestParams(oauthParameters), oauth_token_secret);
        }
        const orderedParameters = OAuthUtils.sortRequestParams(OAuthUtils.makeArrayOfArgumentsHash(oauthParameters));
        orderedParameters[orderedParameters.length]= ['oauth_signature', sig];
        return orderedParameters;
    }

    _performSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type) {
        return new Promise((resolve, reject) => {
            const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);
            if (!post_content_type) {
                post_content_type = 'application/x-www-form-urlencoded';
            }
            const parsedUrl = new URL(url);
            if (parsedUrl.protocol === 'http:' && !parsedUrl.port) {
                parsedUrl.port = '80';
            }
            if (parsedUrl.protocol === 'https:' && !parsedUrl.port) {
                parsedUrl.port = '443';
            }
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
            for (const key of Object.keys(extra_params)) {
                if (OAuthUtils.isParameterNameAnOAuthParameter(key)) {
                    delete extra_params[key];
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
            const isHttps = parsedUrl.protocol === 'https:';
            const request = this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, isHttps);
            const clientOptions = this._clientOptions;
            let data = '';
            // Some hosts *cough* google appear to close the connection early / send no content-length header
            // allow this behaviour.
            const isEarlyClose = OAuthUtils.isAnEarlyCloseHost(parsedUrl.hostname);
            const responseHandler = async (response) => {
                if (this._responseIsOkay(response)) {
                    return resolve({data, response});
                }
                else if (this._responseIsRedirect(response, clientOptions)) {
                    try {
                        const ret = await this._performSecureRequest(oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type);
                        return resolve(ret);
                    }
                    catch (e) {
                        return reject(e);
                    }
                }
                return reject({data, response});
            }
            request.on('response', (response) => {
                response.setEncoding('utf8');
                response.on('data', (chunk) => {
                    data += chunk;
                });
                response.on('end', async () => {
                    await responseHandler(response);
                });
                response.on('close', async () => {
                    if (isEarlyClose) {
                        await responseHandler(response);
                    }
                });
            });
            request.on('error', (err) => {
                return reject(err);
            });
            if ((method === 'POST' || method === 'PUT') && post_body !== null && post_body !== '') {
                request.write(post_body);
            }
            request.end();
        });
    }

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

    async getOAuthAccessToken(oauth_token, oauth_token_secret, oauth_verifier) {
        try {
            const extraParams = {};
            extraParams.oauth_verifier = oauth_verifier;
            const { data, response } = await this._performSecureRequest(oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null);
            const results = querystring.parse(data);
            const oauth_access_token = results.oauth_token;
            delete results.oauth_token;
            const oauth_access_token_secret = results.oauth_token_secret;
            delete results.oauth_token_secret;
            return { oauth_access_token, oauth_access_token_secret, results, response };
        }
        catch (e) {
            throw e;
        }
    }

    delete(url, oauth_token, oauth_token_secret) {
        return this._performSecureRequest(oauth_token, oauth_token_secret, 'DELETE', url, null, '', null);
    }

    get(url, oauth_token, oauth_token_secret) {
        return this._performSecureRequest(oauth_token, oauth_token_secret, 'GET', url, null, '', null);
    }

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
        return this._performSecureRequest(oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type);
    }

    async put(url, oauth_token, oauth_token_secret, post_body, post_content_type) {
        return this._putOrPost('PUT', url, oauth_token, oauth_token_secret, post_body, post_content_type);
    }

    async post(url, oauth_token, oauth_token_secret, post_body, post_content_type) {
        return this._putOrPost('POST', url, oauth_token, oauth_token_secret, post_body, post_content_type);
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
     *
     **/
    async getOAuthRequestToken(extraParams) {
        if (typeof extraParams === 'function'){
            extraParams = {};
        }
        // Callbacks are 1.0A related
        if (this._authorize_callback) {
            extraParams.oauth_callback = this._authorize_callback;
        }
        try {
            const { data, response } = await this._performSecureRequest(null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null);
            const results = querystring.parse(data);
            const {oauth_token} = results;
            const {oauth_token_secret} = results;
            delete results.oauth_token;
            delete results.oauth_token_secret;
            return { oauth_token, oauth_token_secret, results, response };
        }
        catch (e) {
            throw e;
        }
    }

    signUrl(url, oauth_token, oauth_token_secret, method) {
        if (method === undefined) {
            method = 'GET';
        }
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        const parsedUrl = URL.parse(url, false);
        let query = '';
        for (let i = 0; i < orderedParameters.length; i++) {
            query += `${orderedParameters[i][0]}=${OAuthUtils.encodeData(orderedParameters[i][1])}&`;
        }
        query = query.substring(0, query.length-1);
        return `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}?${query}`;
    }

    authHeader(url, oauth_token, oauth_token_secret, method) {
        if (method === undefined) {
            method = 'GET';
        }
        const orderedParameters = this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
        return this._buildAuthorizationHeaders(orderedParameters);
    }

}

module.exports = OAuth;