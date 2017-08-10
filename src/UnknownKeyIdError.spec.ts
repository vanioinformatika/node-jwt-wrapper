import * as chai from "chai"
import * as jwt from "jsonwebtoken"
import "mocha"

import {UnknownKeyIdError} from "./UnknownKeyIdError"

const {expect} = chai

const keyId = "keyid_1"

function throwUnknownKeyIdError() {
    throw new UnknownKeyIdError(keyId)
}

describe("UnknownKeyIdError", () => {
    it("a new instance should have the appropriate properties", () => {
        try {
            throwUnknownKeyIdError()
        } catch (err) {
            expect(err.name).to.equal("UnknownKeyIdError")
            expect(err instanceof UnknownKeyIdError).to.equal(true)
            expect(err instanceof jwt.JsonWebTokenError).to.equal(true)
            expect(err instanceof Error).to.equal(true)
            expect(err.stack).to.not.equal(null)
            expect(err.stack).to.not.equal(undefined)
            expect(err.toString()).to.equal(`UnknownKeyIdError: unknown key id: ${keyId}`)
            expect(err.keyId).to.equal(keyId)
            expect(err.message).to.equal(`unknown key id: ${keyId}`)
            expect(err.stack.split("\n")[0]).to.equal(`UnknownKeyIdError: unknown key id: ${keyId}`)
            expect(err.stack.split("\n")[1].indexOf("throwUnknownKeyIdError")).to.equal(7)
        }
    })
})
