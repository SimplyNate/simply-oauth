const { TestResponse, TestRequest } = require('./util');
const events = require('events');
const OAuth = require('../src/oauth');
const OAuthEcho = require('../src/oauthecho');
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

describe('OAuth', () => {
    it('followsRedirects should be enabled by default', () => {
        const oauth = new OAuth(null, null, null, null, null, null, 'PLAINTEXT');
        expect(oauth._clientOptions.followRedirects).toBeTruthy();
    });
    it('should create a valid RSA-SHA1 signature', () => {
        const oauth = new OAuth(null, null, null, null, null, null, 'RSA-SHA1');
        const signatureBase = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal';
        const oauthSignature = oauth._createSignature(signatureBase, 'xyz4992k83j47x0b');
        expect(oauthSignature).toBe('qS4rhWog7GPgo4ZCJvUdC/1ZAax/Q4Ab9yOBvgxSopvmKUKp5rso+Zda46GbyN2hnYDTiA/g3P/d/YiPWa454BEBb/KWFV83HpLDIoqUUhJnlXX9MqRQQac0oeope4fWbGlfTdL2PXjSFJmvfrzybERD/ZufsFtVrQKS3QBpYiw=');
        const verifier = crypto.createVerify('RSA-SHA1').update(signatureBase);
        const valid = verifier.verify(RsaPublicKey, oauthSignature, 'base64');
        expect(valid).toBeTruthy();
    });
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
    'When normalising the request parameters': {
        topic: new OAuth(null, null, null, null, null, null, 'HMAC-SHA1'),
        'the resulting parameters should be encoded and ordered as per http://tools.ietf.org/html/rfc5849#section-3.1 (3.4.1.3.2)'(oa) {
            const parameters= {b5 : '=%3D',
                a3: ['a', '2 q'],
                'c@': '',
                a2: 'r b',
                oauth_consumer_key: '9djdj82h48djs9d2',
                oauth_token:'kkk9d7dh3k39sjv7',
                oauth_signature_method: 'HMAC-SHA1',
                oauth_timestamp: '137131201',
                oauth_nonce: '7d8f3e4a',
                c2 :  ''};
            const normalisedParameterString= oa._normaliseRequestParams(parameters);
            assert.equal(normalisedParameterString, 'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7');
        }
    },
    'When preparing the parameters for use in signing': {
        topic: new OAuth(null, null, null, null, null, null, 'HMAC-SHA1'),
        'We need to be wary of node\'s auto object creation from foo[bar] style url parameters'(oa) {
            const result= oa._prepareParameters( '', '', '', 'http://foo.com?foo[bar]=xxx&bar[foo]=yyy', {} );
            assert.equal( result[0][0], 'bar[foo]')
            assert.equal( result[0][1], 'yyy')
            assert.equal( result[1][0], 'foo[bar]')
            assert.equal( result[1][1], 'xxx')
        }
    },
    'When signing a url': {
        topic() {
            const oa= new OAuth(null, null, 'consumerkey', 'consumersecret', '1.0', null, 'HMAC-SHA1');
            oa._getTimestamp= function(){ return '1272399856'; }
            oa._getNonce= function(){ return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; }
            return oa;
        },
        'Provide a valid signature when no token present'(oa) {
            assert.equal( oa.signUrl('http://somehost.com:3323/foo/poop?bar=foo'), 'http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_version=1.0&oauth_signature=7ytO8vPSLut2GzHjU9pn1SV9xjc%3D');
        },
        'Provide a valid signature when a token is present'(oa) {
            assert.equal( oa.signUrl('http://somehost.com:3323/foo/poop?bar=foo', 'token'), 'http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=9LwCuCWw5sURtpMroIolU3YwsdI%3D');
        },
        'Provide a valid signature when a token and a token secret is present'(oa) {
            assert.equal( oa.signUrl('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret'), 'http://somehost.com:3323/foo/poop?bar=foo&oauth_consumer_key=consumerkey&oauth_nonce=ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1272399856&oauth_token=token&oauth_version=1.0&oauth_signature=zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D');
        }
    },
    'When getting a request token': {
        topic() {
            const oa= new OAuth(null, null, 'consumerkey', 'consumersecret', '1.0', null, 'HMAC-SHA1');
            oa._getTimestamp= function(){ return '1272399856'; }
            oa._getNonce= function(){ return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; }
            oa._performSecureRequest= function(){ return this.requestArguments = arguments; }
            return oa;
        },
        'Use the HTTP method in the client options'(oa) {
            oa.setClientOptions({ requestTokenHttpMethod: 'GET' });
            oa.getOAuthRequestToken(() => {});
            assert.equal(oa.requestArguments[2], 'GET');
        },
        'Use a POST by default'(oa) {
            oa.setClientOptions({});
            oa.getOAuthRequestToken(() => {});
            assert.equal(oa.requestArguments[2], 'POST');
        }
    },
    'When getting an access token': {
        topic() {
            const oa= new OAuth(null, null, 'consumerkey', 'consumersecret', '1.0', null, 'HMAC-SHA1');
            oa._getTimestamp= function(){ return '1272399856'; }
            oa._getNonce= function(){ return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; }
            oa._performSecureRequest= function(){ return this.requestArguments = arguments; }
            return oa;
        },
        'Use the HTTP method in the client options'(oa) {
            oa.setClientOptions({ accessTokenHttpMethod: 'GET' });
            oa.getOAuthAccessToken(() => {});
            assert.equal(oa.requestArguments[2], 'GET');
        },
        'Use a POST by default'(oa) {
            oa.setClientOptions({});
            oa.getOAuthAccessToken(() => {});
            assert.equal(oa.requestArguments[2], 'POST');
        }
    },
    'When get authorization header' : {
        topic() {
            const oa= new OAuth(null, null, 'consumerkey', 'consumersecret', '1.0', null, 'HMAC-SHA1');
            oa._getTimestamp= function(){ return '1272399856'; }
            oa._getNonce= function(){ return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; }
            return oa;
        },
        'Provide a valid signature when a token and a token secret is present'(oa) {
            assert.equal( oa.authHeader('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret'), 'OAuth oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0",oauth_signature="zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D"');
        },
        'Support variable whitespace separating the arguments'(oa) {
            oa._oauthParameterSeperator= ', ';
            assert.equal( oa.authHeader('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret'), 'OAuth oauth_consumer_key="consumerkey", oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1272399856", oauth_token="token", oauth_version="1.0", oauth_signature="zeOR0Wsm6EG6XSg0Vw%2FsbpoSib8%3D"');
        }
    },
    'When get the OAuth Echo authorization header': {
        topic () {
            const realm = 'http://foobar.com/';
            const verifyCredentials = 'http://api.foobar.com/verify.json';
            const oa = new OAuthEcho(realm, verifyCredentials, 'consumerkey', 'consumersecret', '1.0A', 'HMAC-SHA1');
            oa._getTimestamp= function(){ return '1272399856'; }
            oa._getNonce= function(){ return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; }
            return oa;
        },
        'Provide a valid signature when a token and token secret is present' (oa) {
            assert.equal( oa.authHeader('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret'), 'OAuth realm="http://foobar.com/",oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0A",oauth_signature="0rr1LhSxACX2IEWRq3uCb4IwtOs%3D"');
        }
    },
    'When non standard ports are used': {
        topic() {
            const oa= new OAuth(null, null, null, null, null, null, 'HMAC-SHA1'),
                mockProvider= {};

            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                assert.equal(headers.Host, 'somehost.com:8080');
                assert.equal(hostname, 'somehost.com');
                assert.equal(port, '8080');
                return {
                    on() {},
                    end() {}
                };
            }
            return oa;
        },
        'getProtectedResource should correctly define the host headers'(oa) {
            oa.getProtectedResource('http://somehost.com:8080', 'GET', 'oauth_token', null, () => {})
        }
    },
    'When building the OAuth Authorization header': {
        topic: new OAuth(null, null, null, null, null, null, 'HMAC-SHA1'),
        'All provided oauth arguments should be concatentated correctly'(oa) {
            const parameters= [
                ['oauth_timestamp',         '1234567'],
                ['oauth_nonce',             'ABCDEF'],
                ['oauth_version',           '1.0'],
                ['oauth_signature_method',  'HMAC-SHA1'],
                ['oauth_consumer_key',      'asdasdnm2321b3']];
            assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
        },
        '*Only* Oauth arguments should be concatentated, others should be disregarded'(oa) {
            const parameters= [
                ['foo',         '2343'],
                ['oauth_timestamp',         '1234567'],
                ['oauth_nonce',             'ABCDEF'],
                ['bar',             'dfsdfd'],
                ['oauth_version',           '1.0'],
                ['oauth_signature_method',  'HMAC-SHA1'],
                ['oauth_consumer_key',      'asdasdnm2321b3'],
                ['foobar',      'asdasdnm2321b3']];
            assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
        },
        '_buildAuthorizationHeaders should not depends on Array.prototype.toString'(oa) {
            const _toString = Array.prototype.toString;
            Array.prototype.toString = function(){ return '[Array] ' + this.length; }; // toString overwrite example used in jsdom.
            const parameters= [
                ['foo',         '2343'],
                ['oauth_timestamp',         '1234567'],
                ['oauth_nonce',             'ABCDEF'],
                ['bar',             'dfsdfd'],
                ['oauth_version',           '1.0'],
                ['oauth_signature_method',  'HMAC-SHA1'],
                ['oauth_consumer_key',      'asdasdnm2321b3'],
                ['foobar',      'asdasdnm2321b3']];
            assert.equal(oa._buildAuthorizationHeaders(parameters), 'OAuth oauth_timestamp="1234567",oauth_nonce="ABCDEF",oauth_version="1.0",oauth_signature_method="HMAC-SHA1",oauth_consumer_key="asdasdnm2321b3"');
            Array.prototype.toString = _toString;
        }
    },
    'When performing the Secure Request' : {
        topic: new OAuth('http://foo.com/RequestToken',
            'http://foo.com/AccessToken',
            'anonymous',  'anonymous',
            '1.0A', 'http://foo.com/callback', 'HMAC-SHA1'),
        'using the POST method' : {
            'Any passed extra_params should form part of the POST body'(oa) {
                let post_body_written= false;
                const op= oa._createClient;
                try {
                    oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                        return {
                            write(post_body){
                                post_body_written= true;
                                assert.equal(post_body,'scope=foobar%2C1%2C2');
                            }
                        };
                    }
                    oa._performSecureRequest('token', 'token_secret', 'POST', 'http://foo.com/protected_resource', {scope: 'foobar,1,2'});
                    assert.equal(post_body_written, true);
                }
                finally {
                    oa._createClient= op;
                }
            }
        }
    },
    'When performing a secure' : {
        topic: new OAuth('http://foo.com/RequestToken',
            'http://foo.com/AccessToken',
            'anonymous',  'anonymous',
            '1.0A', 'http://foo.com/callback', 'HMAC-SHA1'),
        POST : {
            'if no callback is passed' : {
                'it should return a request object'(oa) {
                    const request= oa.post('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain')
                    assert.isObject(request);
                    assert.equal(request.method, 'POST');
                    request.end();
                }
            },
            'if a callback is passed' : {
                'it should call the internal request\'s end method and return nothing'(oa) {
                    let callbackCalled= false;
                    const op= oa._createClient;
                    try {
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            return {
                                write(){},
                                on() {},
                                end() {
                                    callbackCalled= true;
                                }
                            };
                        }
                        const request= oa.post('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain', (e,d) => {})
                        assert.equal(callbackCalled, true);
                        assert.isUndefined(request);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'if the post_body is a buffer' : {
                'It should be passed through as is, and the original content-type (if specified) should be passed through'(oa) {
                    const op= oa._createClient;
                    try {
                        let callbackCalled= false;
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            assert.equal(headers['Content-Type'], 'image/jpeg')
                            return {
                                write(data){
                                    callbackCalled= true;
                                    assert.equal(data.length, 4);
                                },
                                on() {},
                                end() {
                                }
                            };
                        }
                        const request= oa.post('http://foo.com/blah', 'token', 'token_secret', new Buffer([10,20,30,40]), 'image/jpeg')
                        assert.equal(callbackCalled, true);
                    }
                    finally {
                        oa._createClient= op;
                    }
                },
                'It should be passed through as is, and no content-type is specified.'(oa) {
                    //Should probably actually set application/octet-stream, but to avoid a change in behaviour
                    // will just document (here) that the library will set it to application/x-www-form-urlencoded
                    const op= oa._createClient;
                    try {
                        let callbackCalled= false;
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            assert.equal(headers['Content-Type'], 'application/x-www-form-urlencoded')
                            return {
                                write(data){
                                    callbackCalled= true;
                                    assert.equal(data.length, 4);
                                },
                                on() {},
                                end() {
                                }
                            };
                        }
                        const request= oa.post('http://foo.com/blah', 'token', 'token_secret', new Buffer([10,20,30,40]))
                        assert.equal(callbackCalled, true);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'if the post_body is not a string or a buffer' : {
                'It should be url encoded and the content type set to be x-www-form-urlencoded'(oa) {
                    const op= oa._createClient;
                    try {
                        let callbackCalled= false;
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            assert.equal(headers['Content-Type'], 'application/x-www-form-urlencoded')
                            return {
                                write(data){
                                    callbackCalled= true;
                                    assert.equal(data, 'foo=1%2C2%2C3&bar=1%2B2');
                                },
                                on() {},
                                end() {
                                }
                            };
                        }
                        const request= oa.post('http://foo.com/blah', 'token', 'token_secret', {foo:'1,2,3', bar:'1+2'})
                        assert.equal(callbackCalled, true);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'if the post_body is a string' : {
                'and it contains non ascii (7/8bit) characters' : {
                    'the content length should be the byte count, and not the string length'(oa) {
                        const testString= 'Tôi yêu node';
                        const testStringLength= testString.length;
                        const testStringBytesLength= Buffer.byteLength(testString);
                        assert.notEqual(testStringLength, testStringBytesLength); // Make sure we're testing a string that differs between byte-length and char-length!

                        const op= oa._createClient;
                        try {
                            let callbackCalled= false;
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                assert.equal(headers['Content-length'], testStringBytesLength);
                                return {
                                    write(data){
                                        callbackCalled= true;
                                        assert.equal(data, testString);
                                    },
                                    on() {},
                                    end() {
                                    }
                                };
                            }
                            const request= oa.post('http://foo.com/blah', 'token', 'token_secret', 'Tôi yêu node')
                            assert.equal(callbackCalled, true);
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                },
                'and no post_content_type is specified' : {
                    'It should be written as is, with a content length specified, and the encoding should be set to be x-www-form-urlencoded'(oa) {
                        const op= oa._createClient;
                        try {
                            let callbackCalled= false;
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                assert.equal(headers['Content-Type'], 'application/x-www-form-urlencoded');
                                assert.equal(headers['Content-length'], 23);
                                return {
                                    write(data){
                                        callbackCalled= true;
                                        assert.equal(data, 'foo=1%2C2%2C3&bar=1%2B2');
                                    },
                                    on() {},
                                    end() {
                                    }
                                };
                            }
                            const request= oa.post('http://foo.com/blah', 'token', 'token_secret', 'foo=1%2C2%2C3&bar=1%2B2')
                            assert.equal(callbackCalled, true);
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                },
                'and a post_content_type is specified' : {
                    'It should be written as is, with a content length specified, and the encoding should be set to be as specified'(oa) {
                        const op= oa._createClient;
                        try {
                            let callbackCalled= false;
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                assert.equal(headers['Content-Type'], 'unicorn/encoded');
                                assert.equal(headers['Content-length'], 23);
                                return {
                                    write(data){
                                        callbackCalled= true;
                                        assert.equal(data, 'foo=1%2C2%2C3&bar=1%2B2');
                                    },
                                    on() {},
                                    end() {
                                    }
                                };
                            }
                            const request= oa.post('http://foo.com/blah', 'token', 'token_secret', 'foo=1%2C2%2C3&bar=1%2B2', 'unicorn/encoded')
                            assert.equal(callbackCalled, true);
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                }
            }
        },
        GET : {
            'if no callback is passed' : {
                'it should return a request object'(oa) {
                    const request= oa.get('http://foo.com/blah', 'token', 'token_secret')
                    assert.isObject(request);
                    assert.equal(request.method, 'GET');
                    request.end();
                }
            },
            'if a callback is passed' : {
                'it should call the internal request\'s end method and return nothing'(oa) {
                    let callbackCalled= false;
                    const op= oa._createClient;
                    try {
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            return {
                                on() {},
                                end() {
                                    callbackCalled= true;
                                }
                            };
                        }
                        const request= oa.get('http://foo.com/blah', 'token', 'token_secret', (e,d) => {})
                        assert.equal(callbackCalled, true);
                        assert.isUndefined(request);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
        },
        PUT : {
            'if no callback is passed' : {
                'it should return a request object'(oa) {
                    const request= oa.put('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain')
                    assert.isObject(request);
                    assert.equal(request.method, 'PUT');
                    request.end();
                }
            },
            'if a callback is passed' : {
                'it should call the internal request\'s end method and return nothing'(oa) {
                    let callbackCalled= 0;
                    const op= oa._createClient;
                    try {
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            return {
                                on() {},
                                write(data) {
                                    callbackCalled++;
                                },
                                end() {
                                    callbackCalled++;
                                }
                            };
                        }
                        const request= oa.put('http://foo.com/blah', 'token', 'token_secret', 'BLAH', 'text/plain', (e,d) => {})
                        assert.equal(callbackCalled, 2);
                        assert.isUndefined(request);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'if the post_body is a buffer' : {
                'It should be passed through as is, and the original content-type (if specified) should be passed through'(oa) {
                    const op= oa._createClient;
                    try {
                        let callbackCalled= false;
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            assert.equal(headers['Content-Type'], 'image/jpeg')
                            return {
                                write(data){
                                    callbackCalled= true;
                                    assert.equal(data.length, 4);
                                },
                                on() {},
                                end() {
                                }
                            };
                        }
                        const request= oa.put('http://foo.com/blah', 'token', 'token_secret', new Buffer([10,20,30,40]), 'image/jpeg')
                        assert.equal(callbackCalled, true);
                    }
                    finally {
                        oa._createClient= op;
                    }
                },
                'It should be passed through as is, and no content-type is specified.'(oa) {
                    //Should probably actually set application/octet-stream, but to avoid a change in behaviour
                    // will just document (here) that the library will set it to application/x-www-form-urlencoded
                    const op= oa._createClient;
                    try {
                        let callbackCalled= false;
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            assert.equal(headers['Content-Type'], 'application/x-www-form-urlencoded')
                            return {
                                write(data){
                                    callbackCalled= true;
                                    assert.equal(data.length, 4);
                                },
                                on() {},
                                end() {
                                }
                            };
                        }
                        const request= oa.put('http://foo.com/blah', 'token', 'token_secret', new Buffer([10,20,30,40]))
                        assert.equal(callbackCalled, true);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'if the post_body is not a string' : {
                'It should be url encoded and the content type set to be x-www-form-urlencoded'(oa) {
                    const op= oa._createClient;
                    try {
                        let callbackCalled= false;
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            assert.equal(headers['Content-Type'], 'application/x-www-form-urlencoded')
                            return {
                                write(data) {
                                    callbackCalled= true;
                                    assert.equal(data, 'foo=1%2C2%2C3&bar=1%2B2');
                                }
                            };
                        }
                        const request= oa.put('http://foo.com/blah', 'token', 'token_secret', {foo:'1,2,3', bar:'1+2'})
                        assert.equal(callbackCalled, true);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'if the post_body is a string' : {
                'and no post_content_type is specified' : {
                    'It should be written as is, with a content length specified, and the encoding should be set to be x-www-form-urlencoded'(oa) {
                        const op= oa._createClient;
                        try {
                            let callbackCalled= false;
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                assert.equal(headers['Content-Type'], 'application/x-www-form-urlencoded');
                                assert.equal(headers['Content-length'], 23);
                                return {
                                    write(data) {
                                        callbackCalled= true;
                                        assert.equal(data, 'foo=1%2C2%2C3&bar=1%2B2');
                                    }
                                };
                            }
                            const request= oa.put('http://foo.com/blah', 'token', 'token_secret', 'foo=1%2C2%2C3&bar=1%2B2')
                            assert.equal(callbackCalled, true);
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                },
                'and a post_content_type is specified' : {
                    'It should be written as is, with a content length specified, and the encoding should be set to be as specified'(oa) {
                        const op= oa._createClient;
                        try {
                            let callbackCalled= false;
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                assert.equal(headers['Content-Type'], 'unicorn/encoded');
                                assert.equal(headers['Content-length'], 23);
                                return {
                                    write(data) {
                                        callbackCalled= true;
                                        assert.equal(data, 'foo=1%2C2%2C3&bar=1%2B2');
                                    }
                                };
                            }
                            const request= oa.put('http://foo.com/blah', 'token', 'token_secret', 'foo=1%2C2%2C3&bar=1%2B2', 'unicorn/encoded')
                            assert.equal(callbackCalled, true);
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                }
            }
        },
        DELETE : {
            'if no callback is passed' : {
                'it should return a request object'(oa) {
                    const request= oa.delete('http://foo.com/blah', 'token', 'token_secret')
                    assert.isObject(request);
                    assert.equal(request.method, 'DELETE');
                    request.end();
                }
            },
            'if a callback is passed' : {
                'it should call the internal request\'s end method and return nothing'(oa) {
                    let callbackCalled= false;
                    const op= oa._createClient;
                    try {
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            return {
                                on() {},
                                end() {
                                    callbackCalled= true;
                                }
                            };
                        }
                        const request= oa.delete('http://foo.com/blah', 'token', 'token_secret', (e,d) => {})
                        assert.equal(callbackCalled, true);
                        assert.isUndefined(request);
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            }
        },
        'Request With a Callback' : {
            'and a 200 response code is received' : {
                'it should callback successfully'(oa) {
                    const op= oa._createClient;
                    let callbackCalled = false;
                    try {
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            return new DummyRequest( new DummyResponse(200) );
                        }
                        oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, (error) => {
                            // callback
                            callbackCalled= true;
                            assert.equal(error, undefined);
                        });
                        assert.equal(callbackCalled, true)
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'and a 210 response code is received' : {
                'it should callback successfully'(oa) {
                    const op= oa._createClient;
                    let callbackCalled = false;
                    try {
                        oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                            return new DummyRequest( new DummyResponse(210) );
                        }
                        oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, (error) => {
                            // callback
                            callbackCalled= true;
                            assert.equal(error, undefined);
                        });
                        assert.equal(callbackCalled, true)
                    }
                    finally {
                        oa._createClient= op;
                    }
                }
            },
            'And A 301 redirect is received' : {
                'and there is a location header' : {
                    'it should (re)perform the secure request but with the new location'(oa) {
                        const op= oa._createClient;
                        const psr= oa._performSecureRequest;
                        let responseCounter = 1;
                        let callbackCalled = false;
                        const DummyResponse =function() {
                            if( responseCounter == 1 ){
                                this.statusCode= 301;
                                this.headers= {location:'http://redirectto.com'};
                                responseCounter++;
                            }
                            else {
                                this.statusCode= 200;
                            }
                        }
                        DummyResponse.prototype= events.EventEmitter.prototype;
                        DummyResponse.prototype.setEncoding= function() {}

                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse() );
                            }
                            oa._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
                                if( responseCounter == 1 ) {
                                    assert.equal(url, 'http://originalurl.com');
                                }
                                else {
                                    assert.equal(url, 'http://redirectto.com');
                                }
                                return psr.call(oa, oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback )
                            }

                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, () => {
                                // callback
                                assert.equal(responseCounter, 2);
                                callbackCalled= true;
                            });
                            assert.equal(callbackCalled, true)
                        }
                        finally {
                            oa._createClient= op;
                            oa._performSecureRequest= psr;
                        }
                    }
                },
                'but there is no location header' : {
                    'it should execute the callback, passing the HTTP Response code'(oa) {
                        const op= oa._createClient;
                        let callbackCalled = false;
                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse(301) );
                            }
                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, (error) => {
                                // callback
                                assert.equal(error.statusCode, 301);
                                callbackCalled= true;
                            });
                            assert.equal(callbackCalled, true)
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                },
                'and followRedirect is true' : {
                    'it should (re)perform the secure request but with the new location'(oa) {
                        const op= oa._createClient;
                        const psr= oa._performSecureRequest;
                        let responseCounter = 1;
                        let callbackCalled = false;
                        const DummyResponse =function() {
                            if( responseCounter == 1 ){
                                this.statusCode= 301;
                                this.headers= {location:'http://redirectto.com'};
                                responseCounter++;
                            }
                            else {
                                this.statusCode= 200;
                            }
                        }
                        DummyResponse.prototype= events.EventEmitter.prototype;
                        DummyResponse.prototype.setEncoding= function() {}

                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse() );
                            }
                            oa._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
                                if( responseCounter == 1 ) {
                                    assert.equal(url, 'http://originalurl.com');
                                }
                                else {
                                    assert.equal(url, 'http://redirectto.com');
                                }
                                return psr.call(oa, oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback )
                            }

                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, () => {
                                // callback
                                assert.equal(responseCounter, 2);
                                callbackCalled= true;
                            });
                            assert.equal(callbackCalled, true)
                        }
                        finally {
                            oa._createClient= op;
                            oa._performSecureRequest= psr;
                        }
                    }
                },
                'and followRedirect is false' : {
                    'it should not perform the secure request with the new location'(oa) {
                        const op= oa._createClient;
                        oa.setClientOptions({ followRedirects: false });
                        const DummyResponse =function() {
                            this.statusCode= 301;
                            this.headers= {location:'http://redirectto.com'};
                        }
                        DummyResponse.prototype= events.EventEmitter.prototype;
                        DummyResponse.prototype.setEncoding= function() {}

                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse() );
                            }
                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, (res, data, response) => {
                                // callback
                                assert.equal(res.statusCode, 301);
                            });
                        }
                        finally {
                            oa._createClient= op;
                            oa.setClientOptions({followRedirects:true});
                        }
                    }
                }
            },
            'And A 302 redirect is received' : {
                'and there is a location header' : {
                    'it should (re)perform the secure request but with the new location'(oa) {
                        const op= oa._createClient;
                        const psr= oa._performSecureRequest;
                        let responseCounter = 1;
                        let callbackCalled = false;
                        const DummyResponse =function() {
                            if( responseCounter == 1 ){
                                this.statusCode= 302;
                                this.headers= {location:'http://redirectto.com'};
                                responseCounter++;
                            }
                            else {
                                this.statusCode= 200;
                            }
                        }
                        DummyResponse.prototype= events.EventEmitter.prototype;
                        DummyResponse.prototype.setEncoding= function() {}

                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse() );
                            }
                            oa._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
                                if( responseCounter == 1 ) {
                                    assert.equal(url, 'http://originalurl.com');
                                }
                                else {
                                    assert.equal(url, 'http://redirectto.com');
                                }
                                return psr.call(oa, oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback )
                            }

                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, () => {
                                // callback
                                assert.equal(responseCounter, 2);
                                callbackCalled= true;
                            });
                            assert.equal(callbackCalled, true)
                        }
                        finally {
                            oa._createClient= op;
                            oa._performSecureRequest= psr;
                        }
                    }
                },
                'but there is no location header' : {
                    'it should execute the callback, passing the HTTP Response code'(oa) {
                        const op= oa._createClient;
                        let callbackCalled = false;
                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse(302) );
                            }
                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, (error) => {
                                // callback
                                assert.equal(error.statusCode, 302);
                                callbackCalled= true;
                            });
                            assert.equal(callbackCalled, true)
                        }
                        finally {
                            oa._createClient= op;
                        }
                    }
                },
                'and followRedirect is true' : {
                    'it should (re)perform the secure request but with the new location'(oa) {
                        const op= oa._createClient;
                        const psr= oa._performSecureRequest;
                        let responseCounter = 1;
                        let callbackCalled = false;
                        const DummyResponse =function() {
                            if( responseCounter == 1 ){
                                this.statusCode= 302;
                                this.headers= {location:'http://redirectto.com'};
                                responseCounter++;
                            }
                            else {
                                this.statusCode= 200;
                            }
                        }
                        DummyResponse.prototype= events.EventEmitter.prototype;
                        DummyResponse.prototype.setEncoding= function() {}

                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse() );
                            }
                            oa._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
                                if( responseCounter == 1 ) {
                                    assert.equal(url, 'http://originalurl.com');
                                }
                                else {
                                    assert.equal(url, 'http://redirectto.com');
                                }
                                return psr.call(oa, oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback )
                            }

                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, () => {
                                // callback
                                assert.equal(responseCounter, 2);
                                callbackCalled= true;
                            });
                            assert.equal(callbackCalled, true)
                        }
                        finally {
                            oa._createClient= op;
                            oa._performSecureRequest= psr;
                        }
                    }
                },
                'and followRedirect is false' : {
                    'it should not perform the secure request with the new location'(oa) {
                        const op= oa._createClient;
                        oa.setClientOptions({ followRedirects: false });
                        const DummyResponse =function() {
                            this.statusCode= 302;
                            this.headers= {location:'http://redirectto.com'};
                        }
                        DummyResponse.prototype= events.EventEmitter.prototype;
                        DummyResponse.prototype.setEncoding= function() {}

                        try {
                            oa._createClient= function( port, hostname, method, path, headers, sshEnabled ) {
                                return new DummyRequest( new DummyResponse() );
                            }
                            oa._performSecureRequest('token', 'token_secret', 'POST', 'http://originalurl.com', {scope: 'foobar,1,2'}, null, null, (res, data, response) => {
                                // callback
                                assert.equal(res.statusCode, 302);
                            });
                        }
                        finally {
                            oa._createClient= op;
                            oa.setClientOptions({followRedirects:true});
                        }
                    }
                }
            }
        }
    }
}).export(module);