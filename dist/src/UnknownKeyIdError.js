"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = require("jsonwebtoken");
/**
 * Error subclass for signaling that the given key id is not known
 */
class UnknownKeyIdError extends jsonwebtoken_1.JsonWebTokenError {
    /**
     * Creates a new instance with the specified key id
     * @param {string} keyId The key id
     */
    constructor(keyId) {
        super("unknown key id: " + keyId);
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
        this.keyId = keyId;
    }
}
exports.UnknownKeyIdError = UnknownKeyIdError;
//# sourceMappingURL=UnknownKeyIdError.js.map