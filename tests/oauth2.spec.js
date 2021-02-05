const OAuth2 = require('../src/oauth2');

describe('OAuth2', () => {
    it('should construct an expected OAuth2 object', () => {
        const clientId = 'clientId';
        const clientSecret = 'clientSecret';
        const baseSite = 'baseSite';
        const authPath = '/auth/path';
        const accessTokenPath = '/token/path';
        const customHeaders = { custom: 'header' };
        const oauth2 = new OAuth2(clientId, clientSecret, baseSite, authPath, accessTokenPath, customHeaders);
        expect(oauth2._clientId).toBe(clientId);
        expect(oauth2._clientSecret).toBe(clientSecret);
        expect(oauth2._baseSite).toBe(baseSite);
        expect(oauth2._authorizeUrl).toBe(authPath);
        expect(oauth2._accessTokenUrl).toBe(accessTokenPath);
        expect(oauth2._customHeaders).toEqual(customHeaders);
    });
    it('should construct an OAuth2 object with default parameters', () => {
        const oauth2 = new OAuth2('', '', '');
        expect(oauth2._authorizeUrl).toBe('/oauth/authorize');
        expect(oauth2._accessTokenUrl).toBe('/oauth/access_token');
        expect(oauth2._accessTokenName).toBe('access_token');
        expect(oauth2._authMethod).toBe('Bearer');
        expect(oauth2._useAuthorizationHeaderForGET).toBeFalsy();
        expect(oauth2._agent).toBeUndefined();
    });
});