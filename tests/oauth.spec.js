const OAuth = require('../src/oauth');
const crypto = require('crypto');

//Valid RSA keypair used to test RSA-SHA1 signature method
const RsaPrivateKey = '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIICXQIBAAKBgQDizE4gQP5nPQhzof/Vp2U2DDY3UY/Gxha2CwKW0URe7McxtnmE\n' +
    'CrZnT1n/YtfrrCNxY5KMP4o8hMrxsYEe05+1ZGFT68ztms3puUxilU5E3BQMhz1t\n' +
    'JMJEGcTt8nZUlM4utli7fHgDtWbhvqvYjRMGn3AjyLOfY8XZvnFkGjipvQIDAQAB\n' +
    'AoGAKgk6FcpWHOZ4EY6eL4iGPt1Gkzw/zNTcUsN5qGCDLqDuTq2Gmk2t/zn68VXt\n' +
    'tVXDf/m3qN0CDzOBtghzaTZKLGhnSewQ98obMWgPcvAsb4adEEeW1/xigbMiaW2X\n' +
    'cu6GhZxY16edbuQ40LRrPoVK94nXQpj8p7w4IQ301Sm8PSECQQD1ZlOj4ugvfhEt\n' +
    'exi4WyAaM45fylmN290UXYqZ8SYPI/VliDytIlMfyq5Rv+l+dud1XDPrWOQ0ImgV\n' +
    'HJn7uvoZAkEA7JhHNmHF9dbdF9Koj86K2Cl6c8KUu7U7d2BAuB6pPkt8+D8+y4St\n' +
    'PaCmN4oP4X+sf5rqBYoXywHlqEei2BdpRQJBAMYgR4cZu7wcXGIL8HlnmROObHSK\n' +
    'OqN9z5CRtUV0nPW8YnQG+nYOMG6KhRMbjri750OpnYF100kEPmRNI0VKQIECQE8R\n' +
    'fQsRleTYz768ahTVQ9WF1ySErMwmfx8gDcD6jjkBZVxZVpURXAwyehopi7Eix/VF\n' +
    'QlxjkBwKIEQi3Ks297kCQQCL9by1bueKDMJO2YX1Brm767pkDKkWtGfPS+d3xMtC\n' +
    'KJHHCqrS1V+D5Q89x5wIRHKxE5UMTc0JNa554OxwFORX\n' +
    '-----END RSA PRIVATE KEY-----';

const RsaPublicKey = '-----BEGIN PUBLIC KEY-----\n' +
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDizE4gQP5nPQhzof/Vp2U2DDY3\n' +
    'UY/Gxha2CwKW0URe7McxtnmECrZnT1n/YtfrrCNxY5KMP4o8hMrxsYEe05+1ZGFT\n' +
    '68ztms3puUxilU5E3BQMhz1tJMJEGcTt8nZUlM4utli7fHgDtWbhvqvYjRMGn3Aj\n' +
    'yLOfY8XZvnFkGjipvQIDAQAB\n' +
    '-----END PUBLIC KEY-----';


describe('OAuth._clientOptions', () => {
    it('followsRedirects should be enabled by default', () => {
        const oauth = new OAuth(null, null, null, null, null, null, 'PLAINTEXT');
        expect(oauth._clientOptions.followRedirects).toBeTruthy();
    });
});
describe('OAuth._createSignature', () => {
    it('should create a valid RSA-SHA1 signature', () => {
        const oauth = new OAuth(null, null, RsaPublicKey, RsaPrivateKey, null, null, 'RSA-SHA1');
        const signatureBase = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal';
        const oauthSignature = oauth._createSignature(signatureBase, 'xyz4992k83j47x0b');
        expect(oauthSignature).toBe('qS4rhWog7GPgo4ZCJvUdC/1ZAax/Q4Ab9yOBvgxSopvmKUKp5rso+Zda46GbyN2hnYDTiA/g3P/d/YiPWa454BEBb/KWFV83HpLDIoqUUhJnlXX9MqRQQac0oeope4fWbGlfTdL2PXjSFJmvfrzybERD/ZufsFtVrQKS3QBpYiw=');
        const verifier = crypto.createVerify('RSA-SHA1').update(signatureBase);
        const valid = verifier.verify(RsaPublicKey, oauthSignature, 'base64');
        expect(valid).toBeTruthy();
    });
});
describe('OAuth._getSignature', () => {
    it('should return expected result string when signature base is PLAINTEXT', () => {
        const oauth = new OAuth(null, null, null, null, null, null, 'PLAINTEXT');
        const result = oauth._getSignature(
            'GET',
            'http://photos.example.net/photos',
            'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=PLAINTEXT&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original',
            'test'
        );
        expect(result).toBe('&test');
    });
});
describe('OAuth._prepareParameters', () => {
    it('should mitigate node auto object creation from foo[bar] style url parameters', () => {
        const oauth = new OAuth(null, null, null, null, null, null, 'HMAC-SHA1');
        const result = oauth._prepareParameters('', '', '', 'http://foo.com?foo[bar]=xxx&bar[foo]=yyy', {});
        expect(result[0][0]).toBe('bar[foo]');
        expect(result[0][1]).toBe('yyy');
        expect(result[1][0]).toBe('foo[bar]');
        expect(result[1][1]).toBe('xxx');
    });
});
describe('OAuth.signUrl', () => {
    const OAuthUtils = require('../src/utils');
    OAuthUtils.getTimestamp = function() { return 1272399856 };
    OAuthUtils.getNonce = function() { return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; };
    const oauth = new OAuth(null, null, 'consumerkey', 'consumersecret', '1.0', null, 'HMAC-SHA1');
    it('should provide a valid signature when no token is present', () => {
        expect(oauth.signUrl('http://somehost.com:3323/foo/poop?bar=foo')).toBe('http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_version=1.0&oauth_signature=7ytO8vPSLut2GzHjU9pn1SV9xjc%3D');
    });
    it('should provide a valid signature when a token is present', () => {
        expect(oauth.signUrl('http://somehost.com:3323/foo/poop?bar=foo', 'token')).toBe('http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=9LwCuCWw5sURtpMroIolU3YwsdI%3D');
    });
    it('should provide a valid signature when a token and a token secret is present', () => {
        expect(oauth.signUrl('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret')).toBe('http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D');
    });
});
describe('OAuth.setClientOptions', () => {
    it('should override the default requestTokenHttpMethod', () => {
        const oauth = new OAuth('', '', 'consumerkey', 'consumersecret', '1.0', '', 'HMAC-SHA1');
        expect(oauth._clientOptions.requestTokenHttpMethod).toBe('POST');
        oauth.setClientOptions({ requestTokenHttpMethod: 'GET' });
        expect(oauth._clientOptions.requestTokenHttpMethod).toBe('GET');
    });
    it('should override the default accessTokenHttpMethod', () => {
        const oauth = new OAuth('', '', 'consumerkey', 'consumersecret', '1.0', '', 'HMAC-SHA1');
        expect(oauth._clientOptions.accessTokenHttpMethod).toBe('POST');
        oauth.setClientOptions({ accessTokenHttpMethod: 'GET' });
        expect(oauth._clientOptions.accessTokenHttpMethod).toBe('GET');
    });
});
/*
describe('OAuth.getOAuthRequestToken', () => {
});
describe('OAuth.getOAuthAccessToken', () => {
});
 */
describe('OAuth.authHeader', () => {
    const OAuthUtils = require('../src/utils');
    OAuthUtils.getTimestamp = function() { return 1272399856 };
    OAuthUtils.getNonce = function() { return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; };
    const oauth = new OAuth('', '', 'consumerkey', 'consumersecret', '1.0', '', 'HMAC-SHA1');
    it('should provide a valid signature when a token and a token secret is present', () => {
        expect(oauth.authHeader('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret')).toBe('OAuth oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0",oauth_signature="zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D"');
    });
    it('should support variable whitespace separating the arguments', () => {
        oauth._oauthParameterSeperator = ', ';
        expect(oauth.authHeader('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret')).toBe('OAuth oauth_consumer_key="consumerkey", oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1272399856", oauth_token="token", oauth_version="1.0", oauth_signature="zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D"');
    });
});
describe('OAuth._buildAuthorizationHeaders', () => {
    const oauth = new OAuth('', '', '', '', '', '', 'HMAC-SHA1');
    it('should concatenate all provided oauth arguments correctly', () => {
        const parameters = [
            ['oauth_timestamp', '1234567'],
            ['oauth_nonce', 'ABCDEF'],
            ['oauth_version', '1.0'],
            ['oauth_signature_method', 'HMAC-SHA1'],
            ['oauth_consumer_key', 'asdasdnm2321b3']
        ];
        expect(oauth._buildAuthorizationHeaders(parameters)).toBe('OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
    });
    it('should only concatenate oauth specific arguments, discarding all others', () => {
        const parameters = [
            ['foo', '2343'],
            ['oauth_timestamp', '1234567'],
            ['oauth_nonce', 'ABCDEF'],
            ['bar', 'dfsdfd'],
            ['oauth_version', '1.0'],
            ['oauth_signature_method', 'HMAC-SHA1'],
            ['oauth_consumer_key', 'asdasdnm2321b3'],
            ['foobar', 'asdasdnm2321b3']
        ];
        expect(oauth._buildAuthorizationHeaders(parameters)).toBe('OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
    });
    it('should not depend on Array.prototype.toString', () => {
        const _toString = Array.prototype.toString;
        Array.prototype.toString = function() { return '[Array] ' + this.length; };
        const parameters = [
            ['foo', '2343'],
            ['oauth_timestamp', '1234567'],
            ['oauth_nonce', 'ABCDEF'],
            ['bar', 'dfsdfd'],
            ['oauth_version', '1.0'],
            ['oauth_signature_method', 'HMAC-SHA1'],
            ['oauth_consumer_key', 'asdasdnm2321b3'],
            ['foobar', 'asdasdnm2321b3']
        ];
        expect(oauth._buildAuthorizationHeaders(parameters)).toBe('OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
        Array.prototype.toString = _toString;

    });
});
describe('OAuth._prepareSecureRequest', () => {
    const oauth = new OAuth(
        'http://foo.com/RequestToken',
        'http://foo.com/AccessToken',
        'anonymous',
        'anonymous',
        '1.0A',
        'http://foo.com/callback',
        'HMAC-SHA1'
    );
    it('should prepare the OAuth headers correctly', () => {
        const { options } = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, Buffer.from([10,20,30,40]), 'image/jpeg');
        const { headers } = options;
        const [authorization_start, authorization] = headers.Authorization.split(' ');
        expect(authorization_start).toBe('OAuth');
        const parsedAuthorization = {
            oauth_signature: undefined  // Prevents WebStorm from throwing a warning
        };
        const parts = authorization.split(',');
        for (const part of parts) {
            const [key, value] = part.split('=');
            parsedAuthorization[key] = value.replace('"', '').replace('"', '');
        }
        expect(parsedAuthorization.oauth_consumer_key).toBe('anonymous');
        expect(parsedAuthorization.oauth_nonce.length).toBe(32);
        expect(parsedAuthorization.oauth_signature_method).toBe('HMAC-SHA1');
        expect(parsedAuthorization.oauth_timestamp).toBeDefined();
        expect(parsedAuthorization.oauth_token).toBe('token');
        expect(parsedAuthorization.oauth_version).toBe('1.0A');
        expect(parsedAuthorization.oauth_signature).toBe('JW3merf6ooBTgGmaHbDlpNPK9sY%3D');
    });
    it('should pass through post_body as is if it is a buffer', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, Buffer.from([10,20,30,40]), 'image/jpeg');
        expect(preparedRequest.options.headers['Content-Type']).toBe('image/jpeg');
        expect(preparedRequest.post_body.length).toBe(4);
    });
    it('should pass through post_body if buffer and no content-type specified', () => {
        // Should probably actually set application/octet-stream, but to avoid a change in behaviour
        // will just document (here) that the library will set it to application/x-www-form-urlencoded
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, Buffer.from([10,20,30,40]), null);
        expect(preparedRequest.options.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
        expect(preparedRequest.post_body.length).toBe(4);
    });
    it('should url encode and auto set content type if post_body is not a string or buffer', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, {foo:'1,2,3', bar:'1+2'}, null);
        expect(preparedRequest.options.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
        expect(preparedRequest.post_body).toBe('foo=1%2C2%2C3&bar=1%2B2');
    });
    it('should correctly count bytes of a non-ascii string post_body', () => {
        const testString = 'Tôi yêu node';
        const testStringLength = testString.length;
        const testStringBytesLength = Buffer.byteLength(testString);
        expect(testStringLength === testStringBytesLength).toBeFalsy();
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, testString, null);
        expect(preparedRequest.options.headers['Content-Length']).toBe(testStringBytesLength);
        expect(preparedRequest.post_body).toBe(testString);
    });
    it('should take a string with no post_content_type specified as is', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, 'foo=1%2C2%2C3&bar=1%2B2', null);
        expect(preparedRequest.options.headers['Content-Type']).toBe('application/x-www-form-urlencoded');
        expect(preparedRequest.options.headers['Content-Length']).toBe(23);
        expect(preparedRequest.post_body).toBe('foo=1%2C2%2C3&bar=1%2B2');
    });
    it('should take a string with a post_content_type specified as is', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah',null, 'foo=1%2C2%2C3&bar=1%2B2', 'unicorn/encoded');
        expect(preparedRequest.options.headers['Content-Type']).toBe('unicorn/encoded');
        expect(preparedRequest.options.headers['Content-Length']).toBe(23);
        expect(preparedRequest.post_body).toBe('foo=1%2C2%2C3&bar=1%2B2');
    });
    it('should prepare a GET request', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'GET', 'http://foo.com/blah', null, null, null);
        expect(preparedRequest.options.method).toBe('GET');
    });
    it('should prepare a POST request', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/blah', null, 'foo', 'text/plain');
        expect(preparedRequest.options.method).toBe('POST');
    });
    it('should prepare a PUT request', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'PUT', 'http://foo.com/blah', null, 'foo', 'text/plain');
        expect(preparedRequest.options.method).toBe('PUT');
    });
    it('should prepare a DELETE request', () => {
        const preparedRequest = oauth._prepareSecureRequest('token', 'token_secret', 'DELETE', 'http://foo.com/blah', null, null, null);
        expect(preparedRequest.options.method).toBe('DELETE');
    });
});

// Test each api for various response codes (200-210, 300 redirects, 400, 500), when location header is specified, when followRedirect is true/false
describe('OAuth.get', () => {
    const oauth = new OAuth(
        'http://foo.com/RequestToken',
        'http://foo.com/AccessToken',
        'anonymous',
        'anonymous',
        '1.0A',
        'http://foo.com/callback',
        'HMAC-SHA1'
    );
    it('should perform a GET request', async () => {
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
        try {
            const {error, data, response} = await oauth.get('https://reqres.in/api/users/2', 'oauth_token', 'oauth_secret');
            expect(error).toBeUndefined();
            expect(JSON.parse(data)).toEqual(expectedData);
            expect(response).toBeDefined();
        }
        catch(e) {
            console.error(e);
        }
    });
    it('should return the status code as error on a 404', async () => {
        try {
            const { error } = await oauth.get('https://reqres.in/api/users/23', 'oauth_token', 'oauth_secret');
            expect(error).toBe(404);
        }
        catch (e) {
            console.error(e);
        }
    });
});
describe('OAuth.post', () => {
    const oauth = new OAuth(
        'http://foo.com/RequestToken',
        'http://foo.com/AccessToken',
        'anonymous',
        'anonymous',
        '1.0A',
        'http://foo.com/callback',
        'HMAC-SHA1'
    );
    it('should perform a POST request', async () => {
        const post_data = {
            name: 'morpheus',
            job: 'leader'
        };
        try {
            const {error, data, response} = await oauth.post('https://reqres.in/api/users/2', 'oauth_token', 'oauth_secret', post_data);
            expect(error).toBeUndefined();
            const parsedData = JSON.parse(data);
            expect(response.statusCode).toBe(201);
            expect(parsedData.name).toBe(post_data.name);
            expect(parsedData.job).toBe(post_data.job);
        }
        catch(e) {
            console.error(e);
        }
    })
});
describe('OAuth.put', () => {
    const oauth = new OAuth(
        'http://foo.com/RequestToken',
        'http://foo.com/AccessToken',
        'anonymous',
        'anonymous',
        '1.0A',
        'http://foo.com/callback',
        'HMAC-SHA1'
    );
    it('should perform a PUT request', async () => {
        const put = {
            name: 'morpheus',
            job: 'zion resident'
        };
        try {
            const {error, data, response} = await oauth.put('https://reqres.in/api/users/2', 'oauth_token', 'oauth_secret', put);
            expect(error).toBeUndefined();
            const parsedData = JSON.parse(data);
            expect(response.statusCode).toBe(200);
            expect(parsedData.name).toBe(put.name);
            expect(parsedData.job).toBe(put.job);
        }
        catch (e) {
            console.error(e);
        }
    });
});
describe('OAuth.delete', () => {
    const oauth = new OAuth(
        'http://foo.com/RequestToken',
        'http://foo.com/AccessToken',
        'anonymous',
        'anonymous',
        '1.0A',
        'http://foo.com/callback',
        'HMAC-SHA1'
    );
    it('should perform a DELETE request', async () => {
        const {data, response} = await oauth.delete('https://reqres.in/api/users/2', 'oauth_token', 'oauth_secret');
        expect(response.statusCode).toBe(204);
        expect(data).toBe('');
    });
});
