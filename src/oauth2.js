const querystring = require('querystring');
const OAuthUtils = require('./utils');

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
     * Prepare an OAuth request
     * @param {string} method
     * @param {string} url
     * @param {object} headers
     * @param {*} post_body
     * @param {string|null} access_token
     * @returns {{object, object, (string|null)}}
     * @private
     */
    _prepareRequest(method, url, headers, post_body=null, access_token=null) {
        const parsedUrl = new URL(url);
        if (parsedUrl.protocol === 'https:' && !parsedUrl.port) {
            parsedUrl.port = '443';
        }
        const http_library = OAuthUtils.chooseHttpLibrary(parsedUrl);
        const realHeaders = {};
        OAuthUtils.combineObjects(this._customHeaders, realHeaders);
        if (headers) {
            OAuthUtils.combineObjects(headers, realHeaders);
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
        //set the agent on the request options
        if (this._agent) {
            options.agent = this._agent;
        }
        return { http_library, options, post_body };
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
        const { http_library, options, post_body } = this._prepareRequest('POST', this._getAccessTokenUrl(), post_headers, post_data);
        const { error, data, response } = await OAuthUtils.executeRequest(http_library, options, post_body);
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
        return { error, access_token, refresh_token, results, response }; // callback results =-=

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
        const { http_library, options, post_body } = this._prepareRequest('GET', url, headers, '', access_token);
        return OAuthUtils.executeRequest(http_library, options, post_body);
    }
}

module.exports = OAuth2;
