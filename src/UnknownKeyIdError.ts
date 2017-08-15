import {JsonWebTokenError} from "jsonwebtoken"

/**
 * Error subclass for signaling that the given key id is not known
 */
export class UnknownKeyIdError extends JsonWebTokenError {

    public keyId: string

    /**
     * Creates a new instance with the specified key id
     * @param {string} keyId The key id
     */
    constructor(keyId: string) {
        super("unknown key id: " + keyId)
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
        this.keyId = keyId
    }
}
