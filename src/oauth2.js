const querystring = require('querystring');
const https = require('https');
const http = require('http');
const OAuthUtils = require('./_utils');

class OAuth2 {

    /**
     * Create an OAuth2 object
     * @param {string} clientId
     * @param {string} clientSecret
     * @param {string} baseSite
     * @param {string} authorizePath
     * @param {string} accessTokenPath
     * @param {object} customHeaders
     */
    constructor(clientId, clientSecret, baseSite, authorizePath='/oauth/authorize', accessTokenPath='/oauth/access_token', customHeaders={}) {
        this._clientId = clientId;
        this._clientSecret = clientSecret;
        this._baseSite = baseSite;
        this._authorizeUrl = authorizePath;
        this._accessTokenUrl = accessTokenPath;
        this._accessTokenName = 'access_token';
        this._authMethod = 'Bearer';
        this._customHeaders = customHeaders;
        this._useAuthorizationHeaderForGET = false;
        //our agent
        this._agent = undefined;
    }

    /**
     * Allows you to set an agent to use instead of the default HTTP or HTTPS agents.
     * Useful when dealing with your own certificates.
     * @param {string} agent
     */
    setAgent(agent) {
        this._agent = agent;
    }

    /**
     * This 'hack' method is required for sites that don't use
     * 'access_token' as the name of the access token (for requests).
     * (http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-7)
     * it isn't clear what the correct value should be atm, so allowing
     * for specific (temporary?) override for now.
     * @param {string} name
     */
    setAccessTokenName(name) {
        this._accessTokenName = name;
    }

    /**
     * Sets the authorization method for Authorization header.
     * e.g. Authorization: Bearer <token>  # "Bearer" is the authorization method.
     * @param {string} authMethod
     */
    setAuthMethod(authMethod) {
        this._authMethod = authMethod;
    }

    /**
     * If you use the OAuth2 exposed 'get' method (and don't construct your own _request call)
     * this will specify whether to use an 'Authorize' header instead of passing the access_token as a query parameter
     * @param {boolean} useIt
     */
    setUseAuthorizationHeaderForGET(useIt) {
        this._useAuthorizationHeaderForGET = useIt;
    }

    /**
     * Returns an Access Token URL string
     * @returns {string}
     * @private
     */
    _getAccessTokenUrl() {
        return `${this._baseSite}${this._accessTokenUrl}`; /* + "?" + querystring.stringify(params); */
    }

    /**
     * Build the authorization header. In particular, build the part after the colon.
     * e.g. Authorization: Bearer <token>  # Build "Bearer <token>"
     * @param {string} token
     */
    buildAuthHeader(token) {
        return `${this._authMethod} ${token}`;
    }

    /**
     * Returns the correct http/s library for the protocol
     * @param {URL} parsedUrl
     * @returns {(https|http)}
     * @private
     */
    _chooseHttpLibrary(parsedUrl) {
        let http_library = https;
        // As this is OAUth2, we *assume* https unless told explicitly otherwise.
        if (parsedUrl.protocol !== 'https:') {
            http_library = http;
        }
        return http_library;
    }

    /**
     * Prepare an OAuth request
     * @param {string} method
     * @param {string} url
     * @param {object} headers
     * @param {*} post_body
     * @param {string|null} access_token
     * @returns {Promise<{data: string, response: Object}>}
     * @private
     */
    _request(method, url, headers, post_body=null, access_token=null) {
        const parsedUrl = new URL(url);
        if (parsedUrl.protocol === 'https:' && !parsedUrl.port) {
            parsedUrl.port = '443';
        }
        const http_library = this._chooseHttpLibrary(parsedUrl);
        const realHeaders = {};
        for (const key of Object.keys(this._customHeaders)) {
            realHeaders[key] = this._customHeaders[key];
        }
        if (headers) {
            for (const key of Object.keys(headers)) {
                realHeaders[key] = headers[key];
            }
        }
        realHeaders.Host = parsedUrl.host;
        if (!realHeaders['User-Agent']) {
            realHeaders['User-Agent'] = 'Node-oauth';
        }
        if (post_body) {
            if (Buffer.isBuffer(post_body)) {
                realHeaders['Content-Length'] = post_body.length;
            }
            else {
                realHeaders['Content-Length'] = Buffer.byteLength(post_body);
            }
        }
        else {
            realHeaders['Content-length'] = 0;
        }
        if (access_token && !('Authorization' in realHeaders)) {
            if (!parsedUrl.query) {
                parsedUrl.query = {};
            }
            parsedUrl.query[this._accessTokenName] = access_token;
        }
        let queryStr = querystring.stringify(parsedUrl.query);
        if (queryStr) {
            queryStr = `?${queryStr}`;
        }
        const options = {
            host: parsedUrl.hostname,
            port: parsedUrl.port,
            path: `${parsedUrl.pathname}${queryStr}`,
            method,
            headers: realHeaders
        };
        return this._executeRequest(http_library, options, post_body);
    }

    /**
     *
     * @param {(http|https)} http_library
     * @param {object} options
     * @param {*} post_body
     * @returns {Promise<{data: string, response: object}>}
     * @private
     */
    _executeRequest(http_library, options, post_body) {
        return new Promise((resolve, reject) => {
            // Some hosts *cough* google appear to close the connection early / send no content-length header
            // allow this behaviour.
            const isEarlyClose = OAuthUtils.isAnEarlyCloseHost(options.host);
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
            //set the agent on the request options
            if (this._agent) {
                options.agent = this._agent;
            }
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

    /**
     * Returns a string authorize URL
     * @param {object} params
     * @returns {string}
     */
    getAuthorizeUrl(params) {
        params = params || {};
        params.client_id = this._clientId;
        return `${this._baseSite}${this._authorizeUrl}?${querystring.stringify(params)}`;
    }

    /**
     * Gets an OAuth Access token
     * @param {string} code
     * @param {object} params
     * @returns {Promise<{access_token: ParsedUrlQuery, refresh_token: ParsedUrlQuery, response: Object, results: ParsedUrlQuery}>}
     */
    async getOAuthAccessToken(code, params) {
        params = params || {};
        params.client_id = this._clientId;
        params.client_secret = this._clientSecret;
        const codeParam = params?.grant_type === 'refresh_token' ? 'refresh_token' : 'code';
        params[codeParam] = code;
        const post_data = querystring.stringify(params);
        const post_headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        };
        // eslint-disable-next-line no-useless-catch
        try {
            const { data, response } = await this._request('POST', this._getAccessTokenUrl(), post_headers, post_data);
            let results;
            try {
                // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
                // responses should be in JSON
                results = JSON.parse(data);
            }
            catch (e) {
                // .... However both Facebook + Github currently use rev05 of the spec
                // and neither seem to specify a content-type correctly in their response headers :(
                // clients of these services will suffer a *minor* performance cost of the exception
                // being thrown
                results = querystring.parse(data);
            }
            const { access_token } = results;
            const { refresh_token } = results;
            delete results.refresh_token;
            return { access_token, refresh_token, results, response }; // callback results =-=
        }
        catch (error) {
            throw error;
        }

    }

    /**
     * Gets a protected resource. Deprecated
     * @param {string} url
     * @param {string} access_token
     * @returns {Promise<{data: string, response: Object}>}
     * @deprecated
     */
    getProtectedResource(url, access_token) {
        return this._request('GET', url, {}, '', access_token);
    }

    /**
     * Send a GET OAuth request
     * @param {string} url
     * @param {(string|null)} access_token
     * @returns {Promise<{data: string, response: Object}>}
     */
    get(url, access_token) {
        const headers = {}
        if (this._useAuthorizationHeaderForGET) {
            headers.Authorization = this.buildAuthHeader(access_token);
            access_token = null;
        }
        return this._request('GET', url, headers, '', access_token);
    }
}

module.exports = OAuth2;
