"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = require("jsonwebtoken");
/**
 * Error subclass for signaling that the kid field is not present in the JWT header
 */
class MissingKeyIdError extends jsonwebtoken_1.JsonWebTokenError {
    constructor() {
        super("missing key id");
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}
exports.MissingKeyIdError = MissingKeyIdError;
//# sourceMappingURL=MissingKeyIdError.js.map