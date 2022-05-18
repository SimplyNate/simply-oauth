import * as http from 'node:http';
import * as https from 'node:https';
import { IncomingMessage } from 'http';
import { URL } from 'node:url';
import { ClientOptions, Options } from './OAuth';

export interface GenericObject {
    [index: string]: any,
}

/**
 * Returns true if this is a host that closes *before* it ends
 */
export function isAnEarlyCloseHost(hostName: string): boolean {
    return hostName && (hostName.match(/.*google(apis)?.com$/))?.length > 0;
}

/**
 * Adds all the key/value pairs of the 'from' object to the 'to' object
 */
export function combineObjects(from: GenericObject, to: GenericObject): GenericObject {
    return {
        ...to,
        ...from,
    };
}

/**
 * Encode special characters
 */
export function encodeData(toEncode?: string): string {
    if (toEncode === null || toEncode === '') {
        return '';
    }
    const result = encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth RFC3986 and Javascript
    return result.replace(/!/g, '%21')
        .replace(/'/g, '%27')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29')
        .replace(/\*/g, '%2A');
}

/**
 * Decode special characters
 */
export function decodeData(toDecode?: string): string {
    if (toDecode) {
        toDecode = toDecode.replace(/\+/g, ' ');
    }
    return decodeURIComponent(toDecode);
}

/**
 * Returns a normalized URL using parsed URL components
 */
export function normalizeUrl(url: string): string {
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
 */
export function createSignatureBase(method: string, url: string, parameters: string): string {
    url = this.encodeData(this.normalizeUrl(url));
    parameters = this.encodeData(parameters);
    return `${method.toUpperCase()}&${url}&${parameters}`;
}

/**
 * Determines whether a parameter is considered an OAuth parameter
 */
export function isParameterNameAnOAuthParameter(parameter: string): boolean {
    const m = parameter.match('^oauth_');
    return !!(m && (m[0] === 'oauth_'));
}

/**
 * Takes an object literal that represents the arguments, and returns an array of argument/value pairs.
 */
export function makeArrayOfArgumentsHash(argumentsHash: GenericObject): any[][] {
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
 */
export function sortRequestParams(argumentPairs: any[]): void {
    // Sort by name, then value.
    argumentPairs.sort((a, b) => {
        if (a[0] === b[0])  {
            return a[1] < b[1] ? -1 : 1;
        }
        return a[0] < b[0] ? -1 : 1;
    });
}

/**
 * Normalizes args to request parameter format
 */
export function normaliseRequestParams(args: GenericObject): string {
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
 */
export const NONCE_CHARS = [
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '0','1','2','3','4','5','6','7','8','9'
];

/**
 * Gets a string-joined list of NONCE characters based on the nonce size
 */
export function getNonce(nonceSize: number): string {
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
 */
export function responseIsOkay(response: IncomingMessage): boolean {
    return response.statusCode >= 200 && response.statusCode <= 299;
}

/**
 * Checks if the status code is in the 300s
 */
export function responseIsRedirect(response: IncomingMessage, clientOptions: ClientOptions): boolean {
    return !!((response.statusCode === 301 || response.statusCode === 302) && clientOptions.followRedirects && response?.headers?.location);
}

/**
 * Gets a timestamp in seconds
 * @returns {number}
 */
export function getTimestamp(): number {
    return Math.floor((new Date()).getTime() / 1000);
}

/**
 * Returns the correct http/s library for the protocol
 */
export function chooseHttpLibrary(parsedUrl: URL) {
    return parsedUrl.protocol === 'https:' ? https : http;
}

export interface OAuthResponse {
    error?: number,
    data: string | GenericObject,
    // eslint-disable-next-line no-undef
    response: Response
}

/**
 * Performs the https oauth request
 */
export async function executeRequest(options: Options, postBody?: GenericObject): Promise<OAuthResponse> {
    if (postBody) {
        options.postBody = postBody;
    }
    const response = await fetch(options.host, options);
    if (response.ok) {
        const data = await response.json();
        return {data, response};
    }
    return {error: response.status, data: response.statusText, response};
}
