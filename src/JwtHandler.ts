import base64url = require("base64url")
import debug = require("debug")
import * as jwt from "jsonwebtoken"

import * as util from "util"
import {shim} from "util.promisify"

import {MissingKeyIdError} from "./MissingKeyIdError"
import {UnknownKeyIdError} from "./UnknownKeyIdError"

export type PubkeyData = { cert: string, alg?: string } | undefined | null
export type PrivkeyData = { key: string, passphrase: string, alg: string } | undefined | null

export type PubkeyResolver = (keyId: string) => PubkeyData | Promise<PubkeyData>
export type PrivkeyResolver = (keyId: string) => PrivkeyData | Promise<PrivkeyData>

// tslint:disable-next-line:max-line-length
type JwtVerifyAsync = <T extends string | object>(token: string, publicKey: string | Buffer, options?: jwt.VerifyOptions) => Promise<T>
type JwtSignAsync = (payload: string | Buffer | object, privateKey: {}, options?: jwt.SignOptions) => Promise<string>

export interface JwtHandlerOptions {
    debugNamePrefix: string
    pubkeyResolver?: PubkeyResolver
    privkeyResolver?: PrivkeyResolver
}

shim() // util.promisify shim

export class JwtHandler {

    private debug: debug.IDebugger

    private pubkeyResolver: PubkeyResolver | null
    private privkeyResolver: PrivkeyResolver | null

    private jwtVerifyAsync = util.promisify(jwt.verify) as JwtVerifyAsync
    private jwtSignAsync = util.promisify(jwt.sign) as JwtSignAsync

    public constructor(options: JwtHandlerOptions)
    public constructor(debugNamePrefix: string,
                       pubkeyResolver?: PubkeyResolver | null,
                       privkeyResolver?: PrivkeyResolver | null)
    public constructor(arg1: string | JwtHandlerOptions, arg2?: PubkeyResolver | null, arg3?: PrivkeyResolver | null) {
        if (typeof arg1 === "object") {
            arg2 = arg1.pubkeyResolver
            arg3 = arg1.privkeyResolver
            arg1 = arg1.debugNamePrefix
        }

        arg2 = arg2 || null
        arg3 = arg3 || null

        this.debug = debug(arg1 + ":jwt.handler")
        this.pubkeyResolver = arg2
        this.privkeyResolver = arg3
    }

    /**
     * Extract key ID from the given JWT
     *
     * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @return {Promise<string, MissingKeyIdError>} Promise to the key id
     */
    public extractKeyId(jwtRaw: string): string {
        try {
            const jwtHeaderBase64 = jwtRaw.split(".", 1)
            const jwtHeader = JSON.parse(base64url.decode(jwtHeaderBase64[0]))
            if (jwtHeader.kid) {
                return jwtHeader.kid
            }
        } catch (err) {
            throw new jwt.JsonWebTokenError("JWT header parsing error", err)
        }

        throw new MissingKeyIdError()
    }

    /**
     * Validates the given JWT
     *
     * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @param {Object} options Validation options (jsonwebtoken module options)
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    public async verify<T extends string | { [key: string]: any }>(jwtRaw: string,
                                                                   options?: jwt.VerifyOptions): Promise<T> {
        if (!jwtRaw) {
            throw new jwt.JsonWebTokenError("Empty JWT")
        }
        const keyId = await this.extractKeyId(jwtRaw)
        debug("verify, key id: " + keyId)
        if (this.pubkeyResolver) {
            const certData = await this.pubkeyResolver(keyId)
            if (!certData) {
                throw new UnknownKeyIdError(keyId)
            }
            debug("cert found")
            return this.jwtVerifyAsync<T>(jwtRaw, certData.cert, options)
        }
        throw new Error("No public key resolver specified")
    }

    /**
     * Creates a new JWT with the given body and signs it with the given key
     *
     * @param {string} tokenBody The body of the JWT token
     * @param {string} keyId The ID of the signing key
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    public async create(tokenBody: string | Buffer | { [key: string]: any }, keyId: string): Promise<string> {
        debug("create, key id: " + keyId)
        if (this.privkeyResolver) {
            const signingKey = await this.privkeyResolver(keyId)
            if (!signingKey) {
                throw new UnknownKeyIdError("Unknown key id")
            }
            debug("priv key found")
            return this.jwtSignAsync(tokenBody, signingKey, {algorithm: signingKey.alg, header: {kid: keyId}})
        }
        throw new Error("No private key resolver specified")
    }

}
