import * as chai from "chai"
import * as chaiAsPromised from "chai-as-promised"
import * as jwt from "jsonwebtoken"
import "mocha"

import {JwtHandler, PrivkeyData, PubkeyData} from "./JwtHandler"
import {MissingKeyIdError} from "./MissingKeyIdError"
import {UnknownKeyIdError} from "./UnknownKeyIdError"

chai.use(chaiAsPromised)
const {expect} = chai

const debugNamePrefix = "test"

// fixtures
const keyId = "abc1234"
const tokenBody = {
    iat: Math.floor(Date.now() / 1000),
    dummy: "dummy",
    iss: "issuer1",
    aud: "audience1",
}

function pubkeyResolver(pubkeyId: string): PubkeyData {
    return (pubkeyId === keyId) ? {cert, alg: "RS256"} : null
}

function privkeyResolver(privkeyId: string): PrivkeyData {
    return (privkeyId === keyId) ? {key: privateKey, passphrase: privateKeyPass, alg: "RS256"} : null
}

describe("JwtHandler", () => {

    describe("extractKeyId", () => {
        const jwtHandler = new JwtHandler(debugNamePrefix, pubkeyResolver, privkeyResolver)
        it("should return the correct key id from the given JWT", () => {
            const jwtRaw = generateJwt(keyId, tokenBody)
            expect(jwtHandler.extractKeyId(jwtRaw)).to.equal(keyId)
        })

        it("should be rejected with MissingKeyIdError if the JWT does not contain a kid property in the header", () => {
            const jwtRaw = generateJwt(null, tokenBody)
            expect(() => jwtHandler.extractKeyId(jwtRaw)).to.throw(MissingKeyIdError)
        })

        it("should be rejected with JsonWebTokenError if the JWT header is not JSON", () => {
            // tslint:disable-next-line:max-line-length
            const jwtRaw = "76576576werwerwterertertert.7868765348765zurtiueziuerziutziuzeriuziuwtzuizi34986349.345765347654376543765735765tzreztwrwueruz"
            expect(() => jwtHandler.extractKeyId(jwtRaw)).to.throw(jwt.JsonWebTokenError)
        })

        it("should be rejected with JsonWebTokenError if the JWT is complete garbage", () => {
            // tslint:disable-next-line:max-line-length
            const jwtRaw = "!\\76576576w!!--///erwerwterertertertöüóAAŐÚÉÁŰ<<7868765348765>> zurtiueziuerz{ }iutziuzer*****iuziuwtzuizi34986349345765347654376543765735765+++====tzreztwrwueruz"
            expect(() => jwtHandler.extractKeyId(jwtRaw)).to.throw(jwt.JsonWebTokenError)
        })
    })

    describe("verify", () => {
        const jwtHandler = new JwtHandler(debugNamePrefix, pubkeyResolver, privkeyResolver)
        it("should return the JWT body if passed a valid JWT", (done) => {
            const jwtRaw = generateJwt(keyId, tokenBody)
            expect(
                jwtHandler.verify(jwtRaw)
            ).to.eventually.deep.equal(tokenBody).notify(done)
        })

        it("should return the JWT body if passed a valid JWT and validation options that matches the JWT", (done) => {
            const jwtRaw = generateJwt(keyId, tokenBody)
            expect(
                jwtHandler.verify(jwtRaw, {issuer: tokenBody.iss})
            ).to.eventually.deep.equal(tokenBody).notify(done)
        })

        it("should be rejected with JsonWebTokenError if the validation options do not match", (done) => {
            const jwtRaw = generateJwt(keyId, tokenBody)
            expect(
                jwtHandler.verify(jwtRaw, {issuer: "expected_issuer"})
            ).to.eventually.rejectedWith(jwt.JsonWebTokenError).notify(done)
        })

        it("should be rejected with TokenExpiredError if the JWT is already expired", (done) => {
            const tokenBodyExpired = {
                iat: Math.floor(Date.now() / 1000),
                dummy: "dummy",
                exp: Math.floor(Date.now() / 1000) - 5000,
            }
            const jwtRaw = generateJwt(keyId, tokenBodyExpired)
            expect(
                jwtHandler.verify(jwtRaw)
            ).to.eventually.rejectedWith(jwt.TokenExpiredError).notify(done)
        })

        it("should be rejected with NotBeforeError if the is not yet valid", (done) => {
            const tokenBodyNbf = {
                iat: Math.floor(Date.now() / 1000),
                dummy: "dummy",
                nbf: Math.floor(Date.now() / 1000) + 1000,
            }
            const jwtRaw = generateJwt(keyId, tokenBodyNbf)
            expect(
                jwtHandler.verify(jwtRaw)
            ).to.eventually.rejectedWith(jwt.NotBeforeError).notify(done)
        })

        it("should be rejected with JsonWebTokenError if the JWT is empty", (done) => {
            expect(
                jwtHandler.verify("")
            ).to.be.rejectedWith(jwt.JsonWebTokenError).notify(done)
        })

        it("should be rejected with JsonWebTokenError if the JWT is null", (done) => {
            expect(
                jwtHandler.verify(null as any)
            ).to.be.rejectedWith(jwt.JsonWebTokenError).notify(done)
        })

        it("should be rejected with JsonWebTokenError if the JWT is undefined", (done) => {
            expect(
                jwtHandler.verify(undefined as any)
            ).to.be.rejectedWith(jwt.JsonWebTokenError).notify(done)
        })

        // tslint:disable-next-line:max-line-length
        it("should be rejected with MissingKeyIdError if the JWT does not contain a kid property in the header", (done) => {
            const jwtRaw = generateJwt(null, tokenBody)
            expect(
                jwtHandler.verify(jwtRaw)
            ).to.eventually.rejectedWith(MissingKeyIdError).notify(done)
        })

        it("should be rejected with UnknownKeyIdError if the key id is unknown", (done) => {
            const jwtRaw = generateJwt("unknown-key-id", tokenBody)
            expect(
                jwtHandler.verify(jwtRaw)
            ).to.eventually.rejectedWith(UnknownKeyIdError).notify(done)
        })

        it("should be throw an Error if no pubkey resolver is specified", (done) => {
            const jwtHandlerNoPubkeyResolver = new JwtHandler(debugNamePrefix, null, privkeyResolver)
            const jwtRaw = generateJwt(keyId, tokenBody)
            expect(
                jwtHandlerNoPubkeyResolver.verify(jwtRaw)
            ).to.eventually.rejectedWith(Error).notify(done)
        })
    })

    describe("create", () => {
        const jwtHandler = new JwtHandler(debugNamePrefix, pubkeyResolver, privkeyResolver)
        it("should create a valid JWT if called with a key id that exists", (done) => {
            jwtHandler.create(tokenBody, keyId)
                .then((result) => {
                    expect(
                        result.match(/^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/)
                    ).to.be.instanceof(Array)
                    done()
                })
        })
        it("should be rejected with UnknownKeyIdError with a key id that does not exist", (done) => {
            const keyIdUnknown = "unknown-key-id"
            expect(
                jwtHandler.create(tokenBody, keyIdUnknown)
            ).to.be.rejectedWith(UnknownKeyIdError).notify(done)
        })
        it("should be rejected with Error if no privkey resolver is specified", (done) => {
            const jwtHandlerNoPrivkeyResolver = new JwtHandler(debugNamePrefix, pubkeyResolver, null)
            expect(
                jwtHandlerNoPrivkeyResolver.create(tokenBody, keyId)
            ).to.be.rejectedWith(Error).notify(done)
        })
        // it("should be rejected with UnknownKeyIdError with a null key id", (done) => {
        //   expect(
        //     jwtHandler.create(tokenBody, null)
        //   ).to.be.rejectedWith(UnknownKeyIdError).notify(done)
        // })
    })
})

function generateJwt(kid: string | null, body: object) {
    const header = kid ? {kid} : undefined
    return jwt.sign(body, {
            key: privateKey, passphrase: privateKeyPass,
        }, {algorithm: "RS256", header}
    )
}

const cert = `
-----BEGIN CERTIFICATE-----
MIID7TCCAtWgAwIBAgIJAKQP6qr+FpHmMA0GCSqGSIb3DQEBCwUAMIGMMQswCQYD
VQQGEwJIVTERMA8GA1UECAwIQlVEQVBFU1QxETAPBgNVBAcMCEJVREFQRVNUMRUw
EwYDVQQKDAxJZG9tU29mdCBaUnQxDDAKBgNVBAsMA0ZOWTEMMAoGA1UEAwwDRk5Z
MSQwIgYJKoZIhvcNAQkBFhVmbnlAdGVzdC5ra3N6Yi5nb3YuaHUwHhcNMTYwODEw
MTQyNTE4WhcNMzYwNDI3MTQyNTE4WjCBjDELMAkGA1UEBhMCSFUxETAPBgNVBAgM
CEJVREFQRVNUMREwDwYDVQQHDAhCVURBUEVTVDEVMBMGA1UECgwMSWRvbVNvZnQg
WlJ0MQwwCgYDVQQLDANGTlkxDDAKBgNVBAMMA0ZOWTEkMCIGCSqGSIb3DQEJARYV
Zm55QHRlc3Qua2tzemIuZ292Lmh1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA2SS4I2IlYeQ6+YlPGKULgixN+qodseUsMYQAAgOVzYpysl7DqpwNid1b
XX/acoTdQpRjhk/LMyU1bJiyWOV4jcZaPNh+HP91o3TknxlP1N1EqDfdKWLKZ0AU
TiO0/8pGqKNc+ywIrfE3ztyMhg3VzpnySjdieEnhYuU15JVcf2dao1RJ063ZydWA
XeSNRaVHqbVsIrBBMX764lXb1rYIzPRJkdPzhwWW3jhmtmeCtMPJUvy/TcINhRxN
5OAjs9AX0hpgW+Wf7xX/fmm4JhZdwFuDZWHfTmFpkfX30FW5d9I8DRJheZh8XclF
poQVQqddAjAT03qm099S6zhJDgaJ2QIDAQABo1AwTjAdBgNVHQ4EFgQUS1s0+5ze
JyNPWLEq7PQNyTpy5sUwHwYDVR0jBBgwFoAUS1s0+5zeJyNPWLEq7PQNyTpy5sUw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAjosrejzVgzvZEd+ePDk
iGTzTV6hQ98EkKU+OdrNYcGVK6UsxzayzbiLbbl7xZhjjpMItdWS1FdSjYuio5nq
XVGfCbLcbcuRWkYq5xz/e16OQLXmZn0G8Rmx1VYvL7/Nlhc05AYdGV01by5KvO0f
DKz333FXn9HmoieAsybwwnDT/s60tB5fQMu5rf5iww3hNUYjfetcOiy173yWInZu
AUfiJsezYhhzcFa4wpMuenjzfbnf2P2ikbb0H7TMKZAsNYw0i+gfTEhNLCdl1f7g
ITA1Y98Lcir+/eX0aQzCAWTfgOiTpBisMZaBf2hr3tOz8m8p8ySpYT7cohXhdW69
rQ==
-----END CERTIFICATE-----
`
const privateKey = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIn0f/al6G3GMCAggA
MBQGCCqGSIb3DQMHBAgVdKxTlIrZygSCBMj7i8a0kTiNxVLfGqd6igSHFrIWzH+J
YSuuz2lcW+FWuCmS8+hEsGuPkOt/yn012NR1QgEc5mdwpvJHTxDLTE5pLm+10XRE
hCSfvaZwRhSFlM9/ApJd01ZB3rXX82eTzoEt7j2fG0vrovV3FRxa6sw6sQvuGqfX
c6QERSA0UQUKDpFktIw3h03XLO29qneC/wwXX3BBUxlogGNsEsa1Tt7TzxPGsjGv
GgFcLKc6PbEgtC/C7QYdTrrNfFE5Nw/WrVmPX2B6BWcDbavIUtlGXvOLQPJ8EQrA
+w1KLIC8bwTBSqP8V2PBq3bI85tkhPibWI10AYmJ0vnKEyj/T6dt0z/RZ2dszzDZ
43LtXk3LHct+AsFA2dS52Ua9rvkGqb3yz0DzgDm1t8YmQOu2FwlkKDcUrKZOO3HR
km85xhpC2dO0m/sTipV+TZZeuXzM+YCLbmazuWwZUEYf5ZX+A3H3mlZ3yscorMS4
xyC0s2DII62PHcKRXsaAFnXFn46QxzH7JTh/DR2YD1RLyOxSV6GbNRA0GFQh7xVV
ftL6uhd1DdC0baGHnXmOmeWqgR415ObAYcpZc1YAKwNvhkfsNwNQMV3GGe4l5lTg
veHWYyjGcQ77uO230tmhhPH/E1ENhvRIjzgQQZ2vtXNEbkJDPhiUDbeTBTWQiR5F
1Goqi2btlb86m6iNcFfbhug7Nex3dtWXwUBoHWnkW4VGjNGpwuW3v5J54SXidNlL
a7PgToRp0ir3OaP2s4gmfOwLZlWz6FZzsXKw8GiGK70Oe9sC3mjqH8sQcq/wxace
ha49k/z9aUPscXsuAkmLzfUvwZ7JeiMTZ3Lg+WLO1mruo2En0T/Tn90gpa79ghDl
EecjbiaWLmnGCc0Seyv8YPxC+sXbI34VEPCNglnDIHzydITcC2qjCLBteme+Xbt4
8j4H5lh4PWn6tWTxn/SwxvuvQTwb9485F3vjR4pZB1B9/Z3W1xsW+ACcDFU3O02Z
UEGm+08UWshJ8h2nDdSEeJS5XgZbs66f3TAxJeGbTE8p7XdQFuF4wZVfdXBY4D8Y
ZOw3al3L+OFDLq06DL5DF9JeAICwZcX2f8ZJPgLwzqhbVA/NAjpdvsJSkg9aFhn5
azSGy+bQG2fNQwSlE74sZ84obLCeGXMTLngd+PEF3pFwzRLbBQEYpBNlmO93fG8t
AYLF1qRaYYshjgXmgCKaSbWTX+xy4jObn5l/ZHj+ItF5QeEp+oMIgikMg8lJbPI7
XcIZT8KqXxDY3ITvPhSY0ubXOsLjXUGn50p50b3j79Q/2XjGZBnazT8NI+XmhGDt
Osx35FBjOzQEpCRsinu83yVEhps4vmUYy/N/6Plg/JMoe8kk34Ezu1JjKAU+w4Vo
7rcGs1+yfud90LHsOgmcIy8AjKwxkBIgju8hutTZ6G3CB0dzbVJnWYZHiA3vlArf
Qs5TB49cUctzAoTiIvOFjkaW7GC9ssV8jp2P4IgtwsUQqM4URjukLx8+1k5PJq5a
EY8qmraXf1kZjo7tpMLVZrg0EDEbJD4K50EX1JPiZqSDymzzfl1/G5Zxpj6iQXKC
8TCvc42IChKvmxu+s48RZxwHK5KGUq/T67rZ1o/SD469tOyoWAuNI7bUp1zmInV1
J6I=
-----END ENCRYPTED PRIVATE KEY-----
`

const privateKeyPass = "test"
