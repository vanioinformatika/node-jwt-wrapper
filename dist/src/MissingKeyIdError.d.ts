import { JsonWebTokenError } from "jsonwebtoken";
/**
 * Error subclass for signaling that the kid field is not present in the JWT header
 */
export declare class MissingKeyIdError extends JsonWebTokenError {
    constructor();
}
