const OAuthEcho = require('../src/oauthecho');

describe('OAuthEcho.authHeader', () => {
    const realm = 'http://foobar.com/';
    const verifyCredentials = 'http://api.foobar.com/verify.json';
    const oauth = new OAuthEcho(realm, verifyCredentials, 'consumerkey', 'consumersecret', '1.0A', 'HMAC-SHA1');
    const OAuthUtils = require('../src/_utils');
    OAuthUtils.getTimestamp = function() { return 1272399856; }
    OAuthUtils.getNonce = function() { return 'ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp'; }
    it('should provide a valid signature when a token and token secret is present', () => {
        expect(oauth.authHeader('http://somehost.com:3323/foo/poop?bar=foo', 'token', 'tokensecret')).toBe('OAuth realm="http://foobar.com/",oauth_consumer_key="consumerkey",oauth_nonce="ybHPeOEkAUJ3k2wJT9Xb43MjtSgTvKqp",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1272399856",oauth_token="token",oauth_version="1.0A",oauth_signature="0rr1LhSxACX2IEWRq3uCb4IwtOs%3D"');
    });
});