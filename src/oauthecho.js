const OAuth = require('oauth');

class OAuthEcho extends OAuth {

    constructor(realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
        super(null, null, consumerKey, consumerSecret, version, null, signatureMethod, nonceSize, customHeaders);
        this._isEcho = true;
        this._realm = realm;
        this._verifyCredentials = verify_credentials;
    }
}

module.exports = OAuthEcho;
