import OAuth, { SignatureMethod } from './OAuth';
import { GenericObject } from './utils';

export default class OAuthEcho extends OAuth {
    constructor(realm: string,
                verify_credentials: string,
                consumerKey: string,
                consumerSecret: string,
                version: string,
                signatureMethod: SignatureMethod,
                nonceSize: number,
                customHeaders: GenericObject) {
        super(null, null, consumerKey, consumerSecret, version, '', signatureMethod, nonceSize, customHeaders);
        this.isEcho = true;
        this.realm = realm;
        this.verifyCredentials = verify_credentials;
    }
}
