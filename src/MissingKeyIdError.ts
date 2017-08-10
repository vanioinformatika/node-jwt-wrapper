import {JsonWebTokenError} from "jsonwebtoken"

/**
 * Error subclass for signaling that the kid field is not present in the JWT header
 */
export class MissingKeyIdError extends JsonWebTokenError {
    constructor() {
        super("missing key id")
        this.name = this.constructor.name
        Error.captureStackTrace(this, this.constructor)
    }
}
