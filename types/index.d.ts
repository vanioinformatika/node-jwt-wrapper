import {JsonWebTokenError, VerifyOptions} from "jsonwebtoken"

export {TokenExpiredError, NotBeforeError, JsonWebTokenError} from "jsonwebtoken"

type PublicKeyResolver = (keyId: string) => { cert: string, alg: string } | Promise<{ cert: string, alg: string }>;
type PrivateKeyResolver = (keyId: string) => { key: string, passphrase: string, alg: string } | Promise<{ key: string, passphrase: string, alg: string }>;

export class MissingKeyIdError extends JsonWebTokenError {
    constructor()
}

export class UnknownKeyIdError extends JsonWebTokenError {
    constructor(keyId: string)
}

export interface HandlerObject {
    extractKeyId(jwtRaw: string): Promise<string>;

    verify(jwtRaw: string, options: VerifyOptions): Promise<string>;

    create(tokenBody: string | Buffer | object, keyId: string): Promise<string>;
}

export function Handler(debugNamePrefix: string, publicKeyResolver?: PublicKeyResolver, privateKeyResolver?: PrivateKeyResolver): HandlerObject;
