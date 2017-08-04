import debug = require('debug')
import base64url = require('base64url')
import * as Promise from 'bluebird'
import * as jwt from 'jsonwebtoken'

import { MissingKeyIdError } from './MissingKeyIdError'
import { UnknownKeyIdError } from './UnknownKeyIdError'

export type PubkeyData = { cert: string, alg: string } | undefined | null
export type PrivkeyData = { key: string, passphrase: string, alg: string } | undefined | null

export type PubkeyResolver = (keyId: string) => PubkeyData | Promise<PubkeyData>
export type PrivkeyResolver = (keyId: string) => PrivkeyData | Promise<PrivkeyData>

type JwtVerifyAsync = (token: string, publicKey: string, options?: jwt.VerifyOptions) => Promise<object | string>
type JwtSignAsync = (payload: object, privateKey: {}, options?: jwt.SignOptions) => Promise<string>

type PrivkeyResolverAsync = (keyId: string) => Promise<PrivkeyData>

export class JwtHandler {

  private debug: debug.IDebugger
  private privkeyResolverAsync?: PrivkeyResolverAsync

  private pubkeyResolver: PubkeyResolver | null
  private privkeyResolver: PrivkeyResolver | null

  private jwtVerifyAsync = Promise.promisify(jwt.verify) as JwtVerifyAsync
  private jwtSignAsync = Promise.promisify(jwt.sign) as JwtSignAsync

  public constructor (debugNamePrefix: string, pubkeyResolver: PubkeyResolver | null, privkeyResolver: PrivkeyResolver | null) {
    this.debug = debug(debugNamePrefix + ':jwt.handler')
    // this.pubkeyResolverAsync = pubkeyResolver ? async (keyId: string) => pubkeyResolver(keyId) : null
    this.pubkeyResolver = pubkeyResolver
    this.privkeyResolver = privkeyResolver
    this.privkeyResolverAsync = privkeyResolver ? Promise.method(privkeyResolver) as PrivkeyResolverAsync : undefined
  }

  /**
   * Extract key ID from the given JWT
   *
   * @param  {type} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
   * @return {Promise<string, MissingKeyIdError>} Promise to the key id
   */
  public extractKeyId (jwtRaw: string): Promise<string> {
    try {
      const jwtHeaderBase64 = jwtRaw.split('.', 1)
      const jwtHeader = JSON.parse(base64url.decode(jwtHeaderBase64[0]))
      if (jwtHeader.kid) {
        return Promise.resolve(jwtHeader.kid)
      } else {
        return Promise.reject(new MissingKeyIdError())
      }
    } catch (err) {
      return Promise.reject(new jwt.JsonWebTokenError('JWT header parsing error', err))
    }
  }

  /**
   * Validates the given JWT
   *
   * @param {string} jwtRaw The JWT in raw form, i.e. Base64 coded parts separated with dots
   * @param {Object} options Validation options (jsonwebtoken module options)
   * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
   */
  public verify (jwtRaw: string, options?: jwt.VerifyOptions): Promise<object> {
    if (!jwtRaw) {
      return Promise.reject(new jwt.JsonWebTokenError('Empty JWT'))
    }
    return this.extractKeyId(jwtRaw)
               .then(keyId => {
                 debug('verify, key id: ' + keyId)
                 if (this.pubkeyResolver) {
                   return Promise.all([keyId, this.pubkeyResolver(keyId)])
                 } else {
                   throw new Error('No public key resolver specified')
                 }
               })
               .then(([keyId, certData]) => {
                 if (!certData) {
                   return Promise.reject(new UnknownKeyIdError(keyId))
                 }
                 debug('cert found')
                 return this.jwtVerifyAsync(jwtRaw, certData.cert, options)
               })
  }

  /**
   * Creates a new JWT with the given body and signs it with the given key
   *
   * @param {string} tokenBody The body of the JWT token
   * @param {string} keyId The ID of the signing key
   * @return {Promise<Object, JsonWebTokenError>} Promise to the JWT body
   */
  public create (tokenBody: object, keyId: string): Promise<string> {
    debug('create, key id: ' + keyId)
    if (this.privkeyResolverAsync) {
      return this.privkeyResolverAsync(keyId)
      .then(signingKey => {
        if (!signingKey) {
          throw new UnknownKeyIdError('Unknown key id')
        }
        debug('priv key found')
        return this.jwtSignAsync(tokenBody, signingKey, {algorithm: signingKey.alg, header: { 'kid': keyId }})
      })
    } else {
      return Promise.reject(new Error('No private key resolver specified'))
    }
  }

}
