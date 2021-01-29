const OAuthUtils = require('../src/_utils');

describe('isAnEarlyCloseHost', () => {
    it('should return true if google.com or googleapis.com appears', () => {
        const google = 'https://google.com';
        const googleApi = 'https://googleapis.com';
        expect(OAuthUtils.isAnEarlyCloseHost(google)).toBeTruthy();
        expect(OAuthUtils.isAnEarlyCloseHost(googleApi)).toBeTruthy();
    });
    it('should return false if google or googleapis are not in the url', () => {
        const notGoogle = 'https://foo.bar/abc';
        expect(OAuthUtils.isAnEarlyCloseHost(notGoogle)).toBeFalsy();
    });
});

describe('combineObjects', () => {
    it('should copy the key:value pairs from the first arg object to the second arg object', () => {
        const fromObject = { a: 'a', b: 'b', c: 'c' };
        const toObject = { d: 'd', e: 'e', f: 'f' };
        OAuthUtils.combineObjects(fromObject, toObject);
        const expected = { a: 'a', b: 'b', c: 'c', d: 'd', e: 'e', f: 'f' };
        expect(toObject).toEqual(expected);
    });
});

describe('createSignatureBase', () => {
    it('should create a valid signature base as described in http://oauth.net/core/1.0/#sig_base_example', () => {
        const result = OAuthUtils.createSignatureBase(
            'GET',
            'http://photos.example.net/photos',
            'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original'
        );
        expect(result).toBe('GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal');
    });
});
describe('normalizeUrl', () => {
    it('should normalize a url', () => {
        const normal1 = OAuthUtils.normalizeUrl('https://somehost.com:443/foo/bar');
        expect(normal1).toBe('https://somehost.com/foo/bar');
        const normal2 = OAuthUtils.normalizeUrl('https://somehost.com:446/foo/bar');
        expect(normal2).toBe('https://somehost.com:446/foo/bar');
        const normal3 = OAuthUtils.normalizeUrl('http://somehost.com:81/foo/bar');
        expect(normal3).toBe('http://somehost.com:81/foo/bar');
        const normal4 = OAuthUtils.normalizeUrl('http://somehost.com');
        expect(normal4).toBe('http://somehost.com/');
    });
});
describe('makeArrayOfArgumentsHash', () => {
    it('should make an array of argument hashes and flatten arrays', () => {
        const parameters = {
            z: 'a',
            a: ['1', '2'],
            '1': 'c'
        };
        const parameterResults= OAuthUtils.makeArrayOfArgumentsHash(parameters);
        expect(parameterResults.length).toBe(4);
        expect(parameterResults[0][0]).toBe('1');
        expect(parameterResults[1][0]).toBe('z');
        expect(parameterResults[2][0]).toBe('a');
        expect(parameterResults[3][0]).toBe('a');
    });
});

describe('sortRequestParams', () => {
    it('should order them by name', () => {
        const parameters = {
            z: 'a',
            a: 'b',
            '1': 'c'
        };
        const parameterResults = OAuthUtils.makeArrayOfArgumentsHash(parameters);
        OAuthUtils.sortRequestParams(parameterResults);
        expect(parameterResults[0][0]).toBe('1');
        expect(parameterResults[1][0]).toBe('a');
        expect(parameterResults[2][0]).toBe('z');
    });
    it('should order by value if two params are the same', () => {
        const parameters = {
            z: 'a',
            a: ['z', 'b', 'b', 'a', 'y'],
            '1': 'c'
        };
        const parameterResults = OAuthUtils.makeArrayOfArgumentsHash(parameters);
        OAuthUtils.sortRequestParams(parameterResults);
        expect(parameterResults[0][0]).toBe('1');
        expect(parameterResults[1][0]).toBe('a');
        expect(parameterResults[1][1]).toBe('a');
        expect(parameterResults[2][0]).toBe('a');
        expect(parameterResults[2][1]).toBe('b');
        expect(parameterResults[3][0]).toBe('a');
        expect(parameterResults[3][1]).toBe('b');
        expect(parameterResults[4][0]).toBe('a');
        expect(parameterResults[4][1]).toBe('y');
        expect(parameterResults[5][0]).toBe('a');
        expect(parameterResults[5][1]).toBe('z');
        expect(parameterResults[6][0]).toBe('z');
    });
});

describe('normalizeRequestParams', () => {
    it('should be encoded and ordered per http://tools.ietf.org/html/rfc5849#section-3.1 (3.4.1.3.2)', () => {
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
        expect(normalisedParameterString).toBe('a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7');
    });
});