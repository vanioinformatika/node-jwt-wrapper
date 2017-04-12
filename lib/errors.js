const JsonWebTokenError = require('jsonwebtoken').JsonWebTokenError

/**
 * Error subclass for signaling that the kid field is not present in the JWT header
 */
class MissingKeyIdError extends JsonWebTokenError {
  constructor () {
    super('missing key id')
    this.name = this.constructor.name
  }
}

/**
 * Error subclass for signaling that the given key id is not known
 */
class UnknownKeyIdError extends JsonWebTokenError {
  /**
   * Creates a new instance with the specified key id
   * @param  {string} keyId The key id
   */
  constructor (keyId) {
    super('unknown key id: ' + keyId)
    this.name = this.constructor.name
    this.keyId = keyId
  }
}

module.exports = {
  MissingKeyIdError, UnknownKeyIdError
}
