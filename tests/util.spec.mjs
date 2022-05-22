import fetch from 'node-fetch';
import test from 'node:test';
import { strict as assert } from 'node:assert';
import * as OAuthUtils from '../src/utils';

test('isAnEarlyCloseHost', async (t) => {
    await t.test('should return true if google.com or googleapis.com appears', () => {
        assert.deepEqual(OAuthUtils.isAnEarlyCloseHost('https://google.com'), true);
        assert.deepEqual(OAuthUtils.isAnEarlyCloseHost('https://googleapis.com'), true);
    });
    await t.test('should return false if google or googleapis are not in the url', () => {
        assert.deepEqual(OAuthUtils.isAnEarlyCloseHost('https://foo.bar/abc'), false);
    });
});

test('combineObjects', async (t) => {
    await t.test('should copy the key:value pairs from the first arg object to the second arg object', () => {
        const fromObject = { a: 'a', b: 'b', c: 'c' };
        const toObject = { d: 'd', e: 'e', f: 'f' };
        OAuthUtils.combineObjects(fromObject, toObject);
        const expected = { a: 'a', b: 'b', c: 'c', d: 'd', e: 'e', f: 'f' };
        assert.deepEqual(toObject, expected);
    });
});

test('encodeData', async (t) => {
    await t.test('should encode special characters', () => {
        const url = 'https://www.foo.bar/?something=another&another=\'(hello)*\'';
        const results = OAuthUtils.encodeData(url);
        assert.equal(results, 'https%3A%2F%2Fwww.foo.bar%2F%3Fsomething%3Danother%26another%3D%27%28hello%29%2A%27');
    });
});

test('decodeData', async (t) => {
    await t.test('should decode special characters into string representation', () => {
        const encoded = 'https%3A%2F%2Fwww.foo.bar%2F%3Fsomething%3Danother%26another%3D%27%28hello%29%2A%27';
        const results = OAuthUtils.decodeData(encoded);
        assert.equal(results, 'https://www.foo.bar/?something=another&another=\'(hello)*\'');
    });
});

test('normalizeUrl', async (t) => {
    await t.test('should normalize a url', () => {
        const normal1 = OAuthUtils.normalizeUrl('https://somehost.com:443/foo/bar');
        assert.equal(normal1, 'https://somehost.com/foo/bar');
        const normal2 = OAuthUtils.normalizeUrl('https://somehost.com:446/foo/bar');
        assert.equal(normal2, 'https://somehost.com:446/foo/bar');
        const normal3 = OAuthUtils.normalizeUrl('https://somehost.com:81/foo/bar');
        assert.equal(normal3, 'https://somehost.com:81/foo/bar');
        const normal4 = OAuthUtils.normalizeUrl('https://somehost.com');
        assert.equal(normal4, 'https://somehost.com/');
    });
});

test('createSignatureBase', async (t) => {
    await t.test('should create a valid signature base as described in https://oauth.net/core/1.0/#sig_base_example', () => {
        const result = OAuthUtils.createSignatureBase(
            'GET',
            'https://photos.example.net/photos',
            'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original'
        );
        assert.equal(result, 'GET&https%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal');
    });
});

test('isParameterNameAnOAuthParameter', async (t) => {
    await t.test('should correctly identify all oauth parameters and reject others', () => {
        const param1 = OAuthUtils.isParameterNameAnOAuthParameter('oauth_param');
        const param2 = OAuthUtils.isParameterNameAnOAuthParameter('other_param');
        const param3 = OAuthUtils.isParameterNameAnOAuthParameter('anotherParamOAUTH_');
        const param4 = OAuthUtils.isParameterNameAnOAuthParameter('param_oauth_');
        const param5 = OAuthUtils.isParameterNameAnOAuthParameter('_oauth_param');
        assert.equal(param1, true);
        assert.equal(param2, false);
        assert.equal(param3, false);
        assert.equal(param4, false);
        assert.equal(param5, false);
    });
});

test('makeArrayOfArgumentsHash', async (t) => {
    await t.test('should make an array of argument hashes and flatten arrays', () => {
        const parameters = {
            z: 'a',
            a: ['1', '2'],
            '1': 'c'
        };
        const parameterResults = OAuthUtils.makeArrayOfArgumentsHash(parameters);
        assert.equal(parameterResults.length, 4);
        assert.equal(parameterResults[0][0], '1');
        assert.equal(parameterResults[1][0], 'z');
        assert.equal(parameterResults[2][0], 'a');
        assert.equal(parameterResults[3][0], 'a');
    });
});

test('sortRequestParams', async (t) => {
    await t.test('should order them by name', () => {
        const parameters = {
            z: 'a',
            a: 'b',
            '1': 'c'
        };
        const parameterResults = OAuthUtils.makeArrayOfArgumentsHash(parameters);
        OAuthUtils.sortRequestParams(parameterResults);
        assert.equal(parameterResults[0][0], '1');
        assert.equal(parameterResults[1][0], 'a');
        assert.equal(parameterResults[2][0], 'z');
    });
    await t.test('should order by value if two params are the same', () => {
        const parameters = {
            z: 'a',
            a: ['z', 'b', 'b', 'a', 'y'],
            '1': 'c'
        };
        const parameterResults = OAuthUtils.makeArrayOfArgumentsHash(parameters);
        OAuthUtils.sortRequestParams(parameterResults);
        assert.equal(parameterResults[0][0], '1');
        assert.equal(parameterResults[1][0], 'a');
        assert.equal(parameterResults[1][1], 'a');
        assert.equal(parameterResults[2][0], 'a');
        assert.equal(parameterResults[2][1], 'b');
        assert.equal(parameterResults[3][0], 'a');
        assert.equal(parameterResults[3][1], 'b');
        assert.equal(parameterResults[4][0], 'a');
        assert.equal(parameterResults[4][1], 'y');
        assert.equal(parameterResults[5][0], 'a');
        assert.equal(parameterResults[5][1], 'z');
        assert.equal(parameterResults[6][0], 'z');
    });
});

test('normalizeRequestParams', async (t) => {
    await t.test('should be encoded and ordered per https://tools.ietf.org/html/rfc5849#section-3.1 (3.4.1.3.2)', () => {
        const parameters = {
            b5 : '=%3D',
            a3: ['a', '2 q'],
            'c@': '',
            a2: 'r b',
            oauth_consumer_key: '9djdj82h48djs9d2',
            oauth_token:'kkk9d7dh3k39sjv7',
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: '137131201',
            oauth_nonce: '7d8f3e4a',
            c2 :  ''
        };
        const normalisedParameterString = OAuthUtils.normaliseRequestParams(parameters);
        assert.equal(normalisedParameterString, 'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7');
    });
});

test('NONCE_CHARS', async (t) => {
    await t.test('should be a list of expected letters a-zA-Z0-9', () => {
        const nonce = OAuthUtils.NONCE_CHARS.join('');
        assert.equal(nonce, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
        assert.equal(OAuthUtils.NONCE_CHARS.length, 62);
    });
});

test('getNonce', async (t) => {
    await t.test('should return a concatenated string of nonce characters based on size', () => {
        const nonce = OAuthUtils.getNonce(16);
        assert.ok(nonce.match(/[a-zA-Z\d]/));
    });
});

test('responseIsOkay', async (t) => {
    await t.test('should respond true for codes between 200 and 299 inclusively', () => {
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 200 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 201 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 202 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 203 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 204 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 205 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 206 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 207 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 208 }), true);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 226 }), true);
    });
    await t.test('should respond false for codes not between 200 and 299', () => {
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 100 }), false);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 301 }), false);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 404 }), false);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 400 }), false);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 500 }), false);
        assert.equal(OAuthUtils.responseIsOkay({ statusCode: 502 }), false);
    });
});

test('responseIsRedirect', async (t) => {
    await t.test('should respond true if response code is 301, 302, if the client follows redirect, and if a location is present in the response', () => {
        const response = { statusCode: 301, headers: { location: 'some.location' }};
        const clientOptions = { followRedirects: true };
        assert.equal(OAuthUtils.responseIsRedirect(response, clientOptions), true);
        response.statusCode = 302;
        assert.equal(OAuthUtils.responseIsRedirect(response, clientOptions), true);
    });
    await t.test('should respond false if response code is not 301 or 302', () => {
        const response = { statusCode: 202, headers: { location: 'some.location' }};
        const clientOptions = { followRedirects: true };
        assert.equal(OAuthUtils.responseIsRedirect(response, clientOptions), false);
    });
    await t.test('should respond false if client does not follow redirect', () => {
        const response = { statusCode: 302, headers: { location: 'some.location' }};
        const clientOptions = { followRedirects: false };
        assert.equal(OAuthUtils.responseIsRedirect(response, clientOptions), false);
    });
    await t.test('should respond false if a location is not provided in the headers', () => {
        const response = { statusCode: 302, headers: {}};
        const responseNoHeader = { statusCode: 302 };
        const clientOptions = { followRedirects: true };
        assert.equal(OAuthUtils.responseIsRedirect(response, clientOptions), false);
        assert.equal(OAuthUtils.responseIsRedirect(responseNoHeader, clientOptions), false);
    });
});

test('getTimestamp', async (t) => {
    await t.test('should return a Unix timestamp in seconds', () => {
        assert.equal(OAuthUtils.getTimestamp() instanceof Number, true);
        assert.equal(OAuthUtils.getTimestamp() > 0, true);
    });
});

describe('chooseHttpLibrary', () => {
    it('should return http or https library depending on the URL protocol', () => {
        const httpURL = new URL('http://some.url');
        const httpsURL = new URL('https://some.url');
        const http = require('http');
        const https = require('https');
        expect(OAuthUtils.chooseHttpLibrary(httpURL)).toEqual(http);
        expect(OAuthUtils.chooseHttpLibrary(httpsURL)).toEqual(https);
    });
});

describe('executeRequest', () => {
    it('should successfully send a GET request', async () => {
        // https://reqres.in/api/users/2
        const options = {
            hostname: 'reqres.in',
            port: 443,
            path: '/api/users/2',
            method: 'GET',
        };
        const expectedData = {
            data: {
                id: 2,
                email: 'janet.weaver@reqres.in',
                first_name: 'Janet',
                last_name: 'Weaver',
                avatar: 'https://reqres.in/img/faces/2-image.jpg'
            },
            support: {
                url: 'https://reqres.in/#support-heading',
                text: 'To keep ReqRes free, contributions towards server costs are appreciated!'
            }
        };
        const {data, response} = await OAuthUtils.executeRequest(https, options);
        const parsedData = JSON.parse(data);
        expect(response.statusCode).toBe(200);
        expect(parsedData).toEqual(expectedData);
    });
    it('should reject on a 404 GET request', async () => {
        // https://reqres.in/api/users/23
        const options = {
            hostname: 'reqres.in',
            port: 443,
            path: '/api/users/23',
            method: 'GET',
        };
        const {error} = await OAuthUtils.executeRequest(https, options);
        expect(error).toBe(404);
    });
    it('should successfully send a POST request', async () => {
        const post = {
            name: 'morpheus',
            job: 'leader'
        };
        const postData = JSON.stringify(post);
        const options = {
            hostname: 'reqres.in',
            port: 443,
            path: '/api/users',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': postData.length
            }
        };
        const {data, response} = await OAuthUtils.executeRequest(https, options, postData);
        const parsedData = JSON.parse(data);
        expect(response.statusCode).toBe(201);
        expect(parsedData.name).toBe(post.name);
        expect(parsedData.job).toBe(post.job);
    });
    it('should successfully  send a PUT request', async () => {
        const put = {
            name: 'morpheus',
            job: 'zion resident'
        };
        const putData = JSON.stringify(put);
        const options = {
            hostname: 'reqres.in',
            port: 443,
            path: '/api/users/2',
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': putData.length
            }
        };
        const {data, response} = await OAuthUtils.executeRequest(https, options, putData);
        const parsedData = JSON.parse(data);
        expect(response.statusCode).toBe(200);
        expect(parsedData.name).toBe(put.name);
        expect(parsedData.job).toBe(put.job);
    });
    it('should successfully send a DELETE request', async () => {
        const options = {
            hostname: 'reqres.in',
            port: 443,
            path: '/api/users/2',
            method: 'DELETE',
        };
        const {data, response} = await OAuthUtils.executeRequest(https, options);
        expect(response.statusCode).toBe(204);
        expect(data).toBe('');
    });
});
