const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const dirtyChai = require('dirty-chai')
chai.use(dirtyChai)
const expect = chai.expect
const JsonWebTokenError = require('jsonwebtoken').JsonWebTokenError
const { MissingKeyIdError, UnknownKeyIdError } = require('./errors')

const keyId = 'keyid_1'

function throwMissingKeyIdError () {
  throw new MissingKeyIdError()
}

function throwUnknownKeyIdError () {
  throw new UnknownKeyIdError(keyId)
}

describe('errors', function () {
  describe('MissingKeyIdError', function () {
    it('a new instance should have the appropriate properties', function () {
      try {
        throwMissingKeyIdError()
      } catch (err) {
        expect(err.name).to.equal('MissingKeyIdError')
        expect(err instanceof JsonWebTokenError).to.be.true()
        expect(err instanceof Error).to.be.true()
        expect(err.stack).to.exist()
        expect(err.toString()).to.equal(`MissingKeyIdError: missing key id`)
        console.log('stack: ', err.stack)
        expect(err.stack.split('\n')[0]).to.equal(`MissingKeyIdError: missing key id`)
        expect(err.stack.split('\n')[1].indexOf('throwMissingKeyIdError')).to.equal(7)
      }
    })
  })

  describe('UnknownKeyIdError', function () {
    it('a new instance should have the appropriate properties', function () {
      try {
        throwUnknownKeyIdError()
      } catch (err) {
        expect(err.name).to.equal('UnknownKeyIdError')
        expect(err instanceof UnknownKeyIdError).to.be.true()
        expect(err instanceof JsonWebTokenError).to.be.true()
        expect(err instanceof Error).to.be.true()
        expect(err.stack).to.exist()
        expect(err.toString()).to.equal(`UnknownKeyIdError: unknown key id: ${keyId}`)
        expect(err.keyId).to.equal(keyId)
        expect(err.message).to.equal(`unknown key id: ${keyId}`)
        expect(err.stack.split('\n')[0]).to.equal(`UnknownKeyIdError: unknown key id: ${keyId}`)
        expect(err.stack.split('\n')[1].indexOf('throwUnknownKeyIdError')).to.equal(7)
      }
    })
  })
})
