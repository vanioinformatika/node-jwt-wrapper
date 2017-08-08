import { JsonWebTokenError } from "jsonwebtoken";
/**
 * Error subclass for signaling that the given key id is not known
 */
export declare class UnknownKeyIdError extends JsonWebTokenError {
    keyId: string;
    /**
     * Creates a new instance with the specified key id
     * @param {string} keyId The key id
     */
    constructor(keyId: string);
}
