/// <reference types="node" />
import * as jwt from "jsonwebtoken";
export declare type PubkeyData = {
    cert: string;
    alg?: string;
} | undefined | null;
export declare type PrivkeyData = {
    key: string;
    passphrase: string;
    alg: string;
} | undefined | null;
export declare type PubkeyResolver = (keyId: string) => PubkeyData | Promise<PubkeyData>;
export declare type PrivkeyResolver = (keyId: string) => PrivkeyData | Promise<PrivkeyData>;
export interface JwtHandlerOptions {
    debugNamePrefix: string;
    pubkeyResolver?: PubkeyResolver;
    privkeyResolver?: PrivkeyResolver;
}
export declare class JwtHandler {
    private debug;
    private pubkeyResolver;
    private privkeyResolver;
    private jwtVerifyAsync;
    private jwtSignAsync;
    constructor(options: JwtHandlerOptions);
    constructor(debugNamePrefix: string, pubkeyResolver?: PubkeyResolver | null, privkeyResolver?: PrivkeyResolver | null);
    /**
     * Extract key ID from the given JWT
     *
     * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @return {Promise<string, MissingKeyIdError>} Promise to the key id
     */
    extractKeyId(jwtRaw: string): string;
    /**
     * Validates the given JWT
     *
     * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @param {Object} options Validation options (jsonwebtoken module options)
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    verify<T extends string | {
        [key: string]: any;
    }>(jwtRaw: string, options?: jwt.VerifyOptions): Promise<T>;
    /**
     * Creates a new JWT with the given body and signs it with the given key
     *
     * @param {string} tokenBody The body of the JWT token
     * @param {string} keyId The ID of the signing key
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    create(tokenBody: string | Buffer | {
        [key: string]: any;
    }, keyId: string): Promise<string>;
}
