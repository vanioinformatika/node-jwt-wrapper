const jwt = require('jsonwebtoken')
const Promise = require('bluebird')
const base64url = require('base64url')

const { MissingKeyIdError, UnknownKeyIdError } = require('./errors')

const jwtVerifyAsync = Promise.promisify(jwt.verify)
const jwtSignAsync = Promise.promisify(jwt.sign)

/**
 * Synchronous or asnyhronous callback for loading certificate+public key pairs
 * @callback JwtHandler~pubkeyResolverCallback
 * @param {string} keyId Key ID
 * @return {string} The found Base64 certificate+pubkey in PEM format
 *                  or null/undefined if the cert/pubkey is not found
 */

/**
 * Synchronous or asnyhronous callback for loading private keys.
 * @callback JwtHandler~privkeyResolverCallback
 * @param {string} keyId Key ID
 * @return {Object} The found privkey in the form {key, passphrase}
 *                  or null/undefined if the key is not found
 */

/**
 * Creates a JWT wrapper instance
 * @param {string} debugNamePrefix Name prefix used for the debug module
 * @param {JwtHandler~pubkeyResolverCallback} Certificate + pubkey resolver callback
 * @param {JwtHandler~privkeyResolverCallback} Private key resolver callback
 * @return {Object} Node module
 */
module.exports = function (debugNamePrefix, pubkeyResolver, privkeyResolver) {
  //
  const debug = require('debug')(debugNamePrefix + ':jwt.handler')
  //
  const pubkeyResolverAsync = pubkeyResolver ? Promise.method(pubkeyResolver) : null
  const privkeyResolverAsync = privkeyResolver ? Promise.method(privkeyResolver) : null

  /**
   * Extract key ID from the given JWT
   *
   * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
   * @return {Promise<Object, MissingKeyIdError>} Promise to the key id
   */
  function extractKeyId (jwtRaw) {
    try {
      const jwtHeaderBase64 = jwtRaw.split('.', 1)
      const jwtHeader = JSON.parse(base64url.decode(jwtHeaderBase64))
      if (jwtHeader.kid) {
        return Promise.resolve(jwtHeader.kid)
      } else {
        return Promise.reject(new MissingKeyIdError())
      }
    } catch (err) {
      return Promise.reject(err)
    }
  }

  /**
   * Validates the given JWT
   *
   * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
   * @param {Object} options Validation options (jsonwebtoken module options)
   * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
   */
  function verify (jwtRaw, options) {
    if (!jwtRaw) {
      return Promise.reject(new jwt.JsonWebTokenError('Empty JWT'))
    }
    return extractKeyId(jwtRaw)
           .then(keyId => {
             debug('verify, key id: ' + keyId)
             return pubkeyResolverAsync(keyId)
                   .then(certData => {
                     if (!certData) {
                       return Promise.reject(new UnknownKeyIdError(keyId))
                     }
                     debug('cert found')
                     return jwtVerifyAsync(jwtRaw, certData.cert, options)
                   })
           })
  }

  /**
   * Creates a new JWT with the given body and signs it with the given key
   *
   * @param {string} tokenBody The body of the JWT token
   * @param {string} keyId The ID of the signing key
   * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
   */
  function create (tokenBody, keyId) {
    debug('create, key id: ' + keyId)
    return privkeyResolverAsync(keyId)
           .then(signingKey => {
             if (!signingKey) {
               return Promise.reject(new UnknownKeyIdError('Unknown key id'))
             }
             debug('priv key found')
             const header = { 'kid': keyId }
             return jwtSignAsync(tokenBody, signingKey, {algorithm: signingKey.alg, header})
           })
  }

  return {
    extractKeyId,
    verify,
    create
  }
}
