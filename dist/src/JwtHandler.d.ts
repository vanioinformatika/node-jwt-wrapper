/// <reference types="bluebird" />
import * as Promise from 'bluebird';
import * as jwt from 'jsonwebtoken';
export interface PubkeyData {
    cert: string;
    alg: string;
}
export interface PrivkeyData {
    key: string;
    passphrase: string;
    alg: string;
}
export declare type PubkeyResolver = (keyId: string) => PubkeyData | Promise<PubkeyData>;
export declare type PrivkeyResolver = (keyId: string) => PrivkeyData | Promise<PrivkeyData>;
export declare class JwtHandler {
    private debug;
    private pubkeyResolverAsync?;
    private privkeyResolverAsync?;
    private pubkeyResolver?;
    private privkeyResolver?;
    private jwtVerifyAsync;
    private jwtSignAsync;
    constructor(debugNamePrefix: string, pubkeyResolver?: PubkeyResolver, privkeyResolver?: PrivkeyResolver);
    /**
     * Extract key ID from the given JWT
     *
     * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @return {Promise<Object, MissingKeyIdError>} Promise to the key id
     */
    private extractKeyId(jwtRaw);
    /**
     * Validates the given JWT
     *
     * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @param {Object} options Validation options (jsonwebtoken module options)
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    verify(jwtRaw: string, options: jwt.VerifyOptions): Promise<object>;
    /**
     * Creates a new JWT with the given body and signs it with the given key
     *
     * @param {string} tokenBody The body of the JWT token
     * @param {string} keyId The ID of the signing key
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    create(tokenBody: object, keyId: string): Promise<string>;
}
