"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const base64url = require("base64url");
const debug = require("debug");
const jwt = require("jsonwebtoken");
const util = require("util");
const util_promisify_1 = require("util.promisify");
const MissingKeyIdError_1 = require("./MissingKeyIdError");
const UnknownKeyIdError_1 = require("./UnknownKeyIdError");
util_promisify_1.shim(); // util.promisify shim
class JwtHandler {
    constructor(arg1, arg2, arg3) {
        this.jwtVerifyAsync = util.promisify(jwt.verify);
        this.jwtSignAsync = util.promisify(jwt.sign);
        if (typeof arg1 === "object") {
            arg2 = arg1.pubkeyResolver;
            arg3 = arg1.privkeyResolver;
            arg1 = arg1.debugNamePrefix;
        }
        arg2 = arg2 || null;
        arg3 = arg3 || null;
        this.debug = debug(arg1 + ":jwt.handler");
        this.pubkeyResolver = arg2;
        this.privkeyResolver = arg3;
    }
    /**
     * Extract key ID from the given JWT
     *
     * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @return {Promise<string, MissingKeyIdError>} Promise to the key id
     */
    extractKeyId(jwtRaw) {
        try {
            const jwtHeaderBase64 = jwtRaw.split(".", 1);
            const jwtHeader = JSON.parse(base64url.decode(jwtHeaderBase64[0]));
            if (jwtHeader.kid) {
                return jwtHeader.kid;
            }
        }
        catch (err) {
            throw new jwt.JsonWebTokenError("JWT header parsing error", err);
        }
        throw new MissingKeyIdError_1.MissingKeyIdError();
    }
    /**
     * Validates the given JWT
     *
     * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
     * @param {Object} options Validation options (jsonwebtoken module options)
     * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
     */
    verify(jwtRaw, options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!jwtRaw) {
                throw new jwt.JsonWebTokenError("Empty JWT");
            }
            const keyId = yield this.extractKeyId(jwtRaw);
            debug("verify, key id: " + keyId);
            if (this.pubkeyResolver) {
                const certData = yield this.pubkeyResolver(keyId);
                if (!certData) {
                    throw new UnknownKeyIdError_1.UnknownKeyIdError(keyId);
                }
                debug("cert found");
                return this.jwtVerifyAsync(jwtRaw, certData.cert, options);
            }
            throw new Error("No public key resolver specified");
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
        return __awaiter(this, void 0, void 0, function* () {
            debug("create, key id: " + keyId);
            if (this.privkeyResolver) {
                const signingKey = yield this.privkeyResolver(keyId);
                if (!signingKey) {
                    throw new UnknownKeyIdError_1.UnknownKeyIdError("Unknown key id");
                }
                debug("priv key found");
                return this.jwtSignAsync(tokenBody, signingKey, { algorithm: signingKey.alg, header: { kid: keyId } });
            }
            throw new Error("No private key resolver specified");
        });
    }
}
exports.JwtHandler = JwtHandler;
//# sourceMappingURL=JwtHandler.js.map