"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const debug = require("debug");
const base64url = require("base64url");
const Promise = require("bluebird");
const jwt = require("jsonwebtoken");
const errors_1 = require("./errors");
class JwtHandler {
    constructor(debugNamePrefix, pubkeyResolver, privkeyResolver) {
        this.jwtVerifyAsync = Promise.promisify(jwt.verify);
        this.jwtSignAsync = Promise.promisify(jwt.sign);
        this.debug = debug(debugNamePrefix + ':jwt.handler');
        // this.pubkeyResolverAsync = pubkeyResolver ? async (keyId: string) => pubkeyResolver(keyId) : null
        this.pubkeyResolver = pubkeyResolver;
        this.privkeyResolver = privkeyResolver;
        this.pubkeyResolverAsync = pubkeyResolver ? Promise.method(pubkeyResolver) : undefined;
        this.privkeyResolverAsync = privkeyResolver ? Promise.method(privkeyResolver) : undefined;
    }
    /**
     * Extract key ID from the given JWT
     *
     * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @return {Promise<Object, MissingKeyIdError>} Promise to the key id
     */
    extractKeyId(jwtRaw) {
        try {
            const jwtHeaderBase64 = jwtRaw.split('.', 1);
            const jwtHeader = JSON.parse(base64url.decode(jwtHeaderBase64[0]));
            if (jwtHeader.kid) {
                return Promise.resolve(jwtHeader.kid);
            }
            else {
                return Promise.reject(new errors_1.MissingKeyIdError());
            }
        }
        catch (err) {
            if (err instanceof SyntaxError) {
                return Promise.reject(new jwt.JsonWebTokenError('JWT header parsing error'));
            }
            else {
                return Promise.reject(err);
            }
        }
    }
    /**
     * Validates the given JWT
     *
     * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @param {Object} options Validation options (jsonwebtoken module options)
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    verify(jwtRaw, options) {
        if (!jwtRaw) {
            return Promise.reject(new jwt.JsonWebTokenError('Empty JWT'));
        }
        return this.extractKeyId(jwtRaw)
            .then(keyId => {
            debug('verify, key id: ' + keyId);
            if (this.pubkeyResolver) {
                return Promise.all([keyId, this.pubkeyResolver(keyId)]);
            }
            else {
                throw new Error('No public key resolver specified');
            }
        })
            .then(([keyId, certData]) => {
            if (!certData) {
                return Promise.reject(new errors_1.UnknownKeyIdError(keyId));
            }
            debug('cert found');
            return this.jwtVerifyAsync(jwtRaw, certData.cert, options);
        });
    }
    /**
     * Creates a new JWT with the given body and signs it with the given key
     *
     * @param {string} tokenBody The body of the JWT token
     * @param {string} keyId The ID of the signing key
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    create(tokenBody, keyId) {
        debug('create, key id: ' + keyId);
        if (this.privkeyResolverAsync) {
            return this.privkeyResolverAsync(keyId)
                .then(signingKey => {
                if (!signingKey) {
                    throw new errors_1.UnknownKeyIdError('Unknown key id');
                }
                debug('priv key found');
                return this.jwtSignAsync(tokenBody, signingKey, { algorithm: signingKey.alg, header: { 'kid': keyId } });
            });
        }
        else {
            return Promise.reject(new Error('No private key resolver specified'));
        }
    }
}
exports.JwtHandler = JwtHandler;
//# sourceMappingURL=JwtHandler.js.map