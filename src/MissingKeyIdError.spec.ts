import * as jwt from 'jsonwebtoken'
import * as chai from 'chai'
const { expect } = chai
import 'mocha'

import { MissingKeyIdError } from './MissingKeyIdError'

function throwMissingKeyIdError () {
  throw new MissingKeyIdError()
}

describe('MissingKeyIdError', function () {
  it('a new instance should have the appropriate properties', function () {
    try {
      throwMissingKeyIdError()
    } catch (err) {
      expect(err.name).to.equal('MissingKeyIdError')
      expect(err instanceof jwt.JsonWebTokenError).to.equal(true)
      expect(err instanceof Error).to.equal(true)
      expect(err.stack).to.not.equal(null)
      expect(err.stack).to.not.equal(undefined)
      expect(err.toString()).to.equal(`MissingKeyIdError: missing key id`)
      expect(err.stack.split('\n')[0]).to.equal(`MissingKeyIdError: missing key id`)
      expect(err.stack.split('\n')[1].indexOf('throwMissingKeyIdError')).to.equal(7)
    }
  })
})
