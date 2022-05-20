import * as crypto from 'node:crypto';
import { URLSearchParams } from 'node:url';
import {
    GenericObject,
    OAuthResponse,
    encodeData,
    createSignatureBase,
    isParameterNameAnOAuthParameter,
    getTimestamp,
    createOptions,
    getNonce, normaliseRequestParams, makeArrayOfArgumentsHash, sortRequestParams, executeRequest
} from './utils';

export type SignatureMethod = 'PLAINTEXT' | 'HMAC-SHA1' | 'RSA-SHA1';

export interface ClientOptions {
    [index: string]: any,
    requestTokenHttpMethod: string,
    accessTokenHttpMethod: string,
    followRedirects: boolean,
}

export interface Headers {
    [index: string]: string | number,
    'X-Verify-Credentials-Authorization'?: string,
    Authorization?: string,
    Host?: string,
    'Content-Length'?: number,
    'Content-Type'?: string,
}

export interface Options {
    url: string
    method: string,
    headers: Headers,
}

interface OAuthParameters {
    [index: string]: any,
    oauth_timestamp: number,
    oauth_nonce: string,
    oauth_version: string,
    oauth_signature_method: string,
    oauth_consumer_key: string,
    oauth_token?: string,
}

interface PreparedRequest {
    options: Options,
    postBody: string | Buffer,
}

export default class OAuth {
    protected isEcho: boolean;
    private readonly requestUrl?: string;
    private readonly accessUrl?: string;
    private readonly consumerKey?: string;
    private readonly consumerSecret?: string;
    private readonly privateKey?: string;
    private readonly version?: string;
    private readonly authorizeCallback?: string;
    private readonly signatureMethod?: string;
    private readonly nonceSize: number;
    private readonly headers?: Headers;
    private readonly defaultClientOptions: ClientOptions = {
        requestTokenHttpMethod: 'POST',
        accessTokenHttpMethod: 'POST',
        followRedirects: true
    };
    private clientOptions: ClientOptions;
    private readonly oauthParameterSeparator = ',';
    protected realm: string = '';
    protected verifyCredentials: string = '';

    constructor(requestUrl?: string, accessUrl?: string, consumerKey?: string, consumerSecret?: string, version?: string, authorize_callback: string = 'oob', signatureMethod?: SignatureMethod, nonceSize: number = 32, customHeaders?: GenericObject) {
        this.isEcho = false;
        this.requestUrl = requestUrl;
        this.accessUrl = accessUrl;
        this.consumerKey = consumerKey;
        this.consumerSecret = encodeData(consumerSecret);
        if (signatureMethod !== 'PLAINTEXT' && signatureMethod !== 'HMAC-SHA1' && signatureMethod !== 'RSA-SHA1') {
            throw new Error(`Un-supported signature method: ${signatureMethod}`);
        }
        if (signatureMethod === 'RSA-SHA1') {
            this.privateKey = consumerSecret;
        }
        this.version = version;
        this.authorizeCallback = authorize_callback;
        this.signatureMethod = signatureMethod;
        this.nonceSize = nonceSize;
        this.headers = customHeaders || {
            Accept : '*/*',
            Connection : 'close',
            'User-Agent' : 'Node authentication'
        };
        this.clientOptions = this.defaultClientOptions;
    }

    /**
     * Generates a signature
     */
    private getSignature(method: string, url: string, parameters: string, tokenSecret: string): string {
        const signatureBase = createSignatureBase(method, url, parameters);
        return this.createSignature(signatureBase, tokenSecret);
    }

    /**
     * Builds the OAuth request authorization header
     */
    private buildAuthorizationHeaders(orderedParameters: string[][]): string {
        let authHeader = 'OAuth ';
        if (this.isEcho) {
            authHeader += `realm="${this.realm}",`;
        }
        for (let i = 0; i < orderedParameters.length; i++) {
            // While all the parameters should be included within the signature, only the oauth_ arguments
            // should appear within the authorization header.
            if (isParameterNameAnOAuthParameter(orderedParameters[i][0])) {
                authHeader += `${encodeData(orderedParameters[i][0])}="${encodeData(orderedParameters[i][1])}"${this.oauthParameterSeparator}`;
            }
        }
        authHeader = authHeader.substring(0, authHeader.length - this.oauthParameterSeparator.length);
        return authHeader;
    }

    /**
     * Create a hash signature
     */
    createSignature(signatureBase: string, tokenSecret: string): string {
        tokenSecret = tokenSecret ? encodeData(tokenSecret) : '';
        // consumerSecret is already encoded
        let key = `${this.consumerSecret}&${tokenSecret}`;
        let hash;
        if (this.signatureMethod === 'PLAINTEXT') {
            hash = key;
        }
        else if (this.signatureMethod === 'RSA-SHA1') {
            key = this.privateKey || '';
            hash = crypto.createSign('RSA-SHA1').update(signatureBase).sign(key, 'base64');
        }
        else {
            hash = crypto.createHmac('sha1', key).update(signatureBase).digest('base64');
        }
        return hash;
    }

    /**
     * Prepares parameters for OAuth request
     */
    private prepareParameters(oauthToken: string, oauthTokenSecret: string, method: string, url: string, extraParams: GenericObject): string[][] {
        const oauthParameters: OAuthParameters = {
            oauth_timestamp: getTimestamp(),
            oauth_nonce: getNonce(this.nonceSize),
            oauth_version: this.version,
            oauth_signature_method: this.signatureMethod,
            oauth_consumer_key: this.consumerKey,
            oauth_token: undefined,
        };
        if (oauthToken) {
            oauthParameters.oauth_token = oauthToken;
        }
        let sig;
        if (this.isEcho) {
            sig = this.getSignature('GET', this.verifyCredentials, normaliseRequestParams(oauthParameters), oauthTokenSecret);
        }
        else {
            if (extraParams) {
                for (const key of Object.keys(extraParams)) {
                    oauthParameters[key] = extraParams[key];
                }
            }
            const parsedUrl = new URL(url);
            if (parsedUrl.search) {
                const extraParameters = new URLSearchParams(parsedUrl.searchParams);
                for (const [key, value] of extraParameters) {
                    oauthParameters[key] = value;
                }
            }
            sig = this.getSignature(method, url, normaliseRequestParams(oauthParameters), oauthTokenSecret);
        }
        const orderedParameters = makeArrayOfArgumentsHash(oauthParameters);
        sortRequestParams(orderedParameters);
        orderedParameters[orderedParameters.length] = ['oauth_signature', sig];
        return orderedParameters;
    }

    /**
     * Formats a request and sends it to an endpoint
     */
    private prepareSecureRequest(oauthToken?: string, oauthTokenSecret?: string, method?: string, url?: string, extraParams?: GenericObject, postBody?: string | object | Buffer, postContentType?: string): PreparedRequest {
        const orderedParameters = this.prepareParameters(oauthToken, oauthTokenSecret, method, url, extraParams);
        if (!postContentType) {
            postContentType = 'application/x-www-form-urlencoded';
        }
        const parsedUrl = new URL(url);
        const headers: Headers = {};
        const authorization = this.buildAuthorizationHeaders(orderedParameters);
        if (this.isEcho) {
            headers['X-Verify-Credentials-Authorization'] = authorization;
        }
        else {
            headers.Authorization = authorization;
        }
        headers.Host = parsedUrl.host
        for (const key of Object.keys(this.headers)) {
            headers[key] = this.headers[key];
        }
        // Filter out any passed extraParams that are really to do with OAuth
        if (extraParams) {
            for (const key of Object.keys(extraParams)) {
                if (isParameterNameAnOAuthParameter(key)) {
                    delete extraParams[key];
                }
            }
        }
        if ((method === 'POST' || method === 'PUT')  && (postBody === null && extraParams !== null)) {
            // Fix the mismatch between the output of querystring.stringify() and OAuthUtils.encodeData()
            postBody = new URLSearchParams(extraParams).toString()
                .replace(/!/g, '%21')
                .replace(/'/g, '%27')
                .replace(/\(/g, '%28')
                .replace(/\)/g, '%29')
                .replace(/\*/g, '%2A');
        }
        if (postBody) {
            if (postBody instanceof Object) {
                postBody = JSON.stringify(postBody);
                postBody = new URLSearchParams(postBody).toString()
                    .replace(/!/g, '%21')
                    .replace(/'/g, '%27')
                    .replace(/\(/g, '%28')
                    .replace(/\)/g, '%29')
                    .replace(/\*/g, '%2A');
                headers['Content-Length'] = Buffer.byteLength(postBody);
            }
            else if (Buffer.isBuffer(postBody)) {
                headers['Content-Length'] = postBody.length;
            }
            else {
                headers['Content-Length'] = Buffer.byteLength(postBody);
            }

        }
        else {
            headers['Content-Length'] = 0;
        }
        headers['Content-Type'] = postContentType;
        const options = createOptions(parsedUrl.toString(), method, headers);
        return <PreparedRequest>{options, postBody}
    }

    /**
     * Sets client options from argument
     */
    setClientOptions(options: ClientOptions): void {
        this.clientOptions = { ...this.defaultClientOptions, ...options };
    }

    /**
     * Sends an OAuth request with DELETE method
     */
    delete(url: string, oauthToken: string, oauthTokenSecret: string): Promise<OAuthResponse> {
        const { options, postBody } = this.prepareSecureRequest(oauthToken, oauthTokenSecret, 'DELETE', url, null, null, null);
        return executeRequest(options, postBody);
    }

    /**
     * Sends an OAuth request with GET method
     */
    get(url: string, oauthToken: string, oauthTokenSecret: string): Promise<OAuthResponse> {
        const { options, postBody } = this.prepareSecureRequest(oauthToken, oauthTokenSecret, 'GET', url, null, null, null);
        return executeRequest(options, postBody);
    }

    /**
     * Sends an OAuth request with PUT method
     */
    put(url: string, oauthToken: string, oauthTokenSecret: string, postBody: string | object, postContentType?: string): Promise<OAuthResponse> {
        return this.putOrPost('PUT', url, oauthToken, oauthTokenSecret, postBody, postContentType);
    }

    /**
     * Sends an OAuth request with POST method
     */
    async post(url: string, oauthToken: string, oauthTokenSecret: string, postBody: string | object, postContentType?: string): Promise<OAuthResponse> {
        return this.putOrPost('POST', url, oauthToken, oauthTokenSecret, postBody, postContentType);
    }

    /**
     * Sends a PUT or POST request depending on the method
     * @param {('PUT'|'POST')} method
     * @param {string} url
     * @param {string} oauthToken
     * @param {string} oauthTokenSecret
     * @param {(string|object)} postBody
     * @param {(string|null)} postContentType
     * @returns {Promise<{data: string, response: Object}>}
     * @private
     */
    private putOrPost(method: string, url: string, oauthToken: string, oauthTokenSecret: string, postBody: string | object, postContentType?: string): Promise<OAuthResponse> {
        let extraParams = null;
        if (postBody instanceof Object) {
            postContentType = 'application/x-www-form-urlencoded';
            extraParams = postBody;
            postBody = null;
        }
        const prepared = this.prepareSecureRequest(oauthToken, oauthTokenSecret, method, url, extraParams, postBody, postContentType);
        return executeRequest(prepared.options, prepared.postBody);
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
     */
    async getOAuthRequestToken(extraParams: GenericObject = {}) {
        // Callbacks are 1.0A related
        if (this.authorizeCallback) {
            extraParams.oauth_callback = this.authorizeCallback;
        }
        const { options, postBody } = this.prepareSecureRequest(null, null, this.clientOptions.requestTokenHttpMethod, this.requestUrl, extraParams, null, null);
        const { error, data, response } = await executeRequest(options, postBody);
        // @ts-ignore
        const { oauth_token, oauth_token_secret } = data;
        return { error, oauth_token, oauth_token_secret, data, response };
    }

    /**
     * Gets an OAuth access token and returns an object containing the results
     */
    async getOAuthAccessToken(oauthToken: string, oauthTokenSecret: string, oauthVerifier: string) {
        const extraParams = {
            oauth_verifier: oauthVerifier,
        };
        const { options, postBody } = this.prepareSecureRequest(oauthToken, oauthTokenSecret, this.clientOptions.accessTokenHttpMethod, this.accessUrl, extraParams, null, null);
        const { error, data, response } = await executeRequest(options, postBody);
        // @ts-ignore
        const { oauth_token, oauth_token_secret } = data;
        return { error, oauth_token, oauth_token_secret, data, response };
    }

    /**
     * Generates a signed URL string
     */
    signUrl(url: string, oauthToken?: string, oauthTokenSecret?: string, method?: string): string {
        method = method ? method : 'GET';
        const orderedParameters = this.prepareParameters(oauthToken, oauthTokenSecret, method, url, {});
        const parsedUrl = new URL(url);
        let query = '';
        for (let i = 0; i < orderedParameters.length; i++) {
            query += `${orderedParameters[i][0]}=${encodeData(orderedParameters[i][1])}&`;
        }
        query = query.substring(0, query.length-1);
        return `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}?${query}`;
    }

    /**
     * Returns the auth header string
     */
    authHeader(url: string, oauthToken: string, oauthTokenSecret: string, method?: string): string {
        method = method ? method : 'GET';
        const orderedParameters = this.prepareParameters(oauthToken, oauthTokenSecret, method, url, {});
        return this.buildAuthorizationHeaders(orderedParameters);
    }

}
