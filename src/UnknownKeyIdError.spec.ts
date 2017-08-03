import * as jwt from 'jsonwebtoken'
import * as chai from 'chai'
const { expect } = chai
import 'mocha'

import { UnknownKeyIdError } from './UnknownKeyIdError'

const keyId = 'keyid_1'

function throwUnknownKeyIdError () {
  throw new UnknownKeyIdError(keyId)
}

describe('UnknownKeyIdError', function () {
  it('a new instance should have the appropriate properties', function () {
    try {
      throwUnknownKeyIdError()
    } catch (err) {
      expect(err.name).to.equal('UnknownKeyIdError')
      expect(err instanceof UnknownKeyIdError).to.be.true
      expect(err instanceof jwt.JsonWebTokenError).to.be.true
      expect(err instanceof Error).to.be.true
      expect(err.stack).to.exist
      expect(err.toString()).to.equal(`UnknownKeyIdError: unknown key id: ${keyId}`)
      expect(err.keyId).to.equal(keyId)
      expect(err.message).to.equal(`unknown key id: ${keyId}`)
      expect(err.stack.split('\n')[0]).to.equal(`UnknownKeyIdError: unknown key id: ${keyId}`)
      expect(err.stack.split('\n')[1].indexOf('throwUnknownKeyIdError')).to.equal(7)
    }
  })
})
