const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
const expect = chai.expect
const jsonwebtoken = require('jsonwebtoken')

const jwt = require('.')

const JwtHandler = jwt.Handler
const debugNamePrefix = 'test'

// fixtures
const keyId = 'abc1234'
const tokenBody = {
  iat: Math.floor(Date.now() / 1000),
  dummy: 'dummy',
  iss: 'issuer1',
  aud: 'audience1'
}
function pubkeyResolver (pubkeyId) {
  if (pubkeyId === keyId) return {cert: cert, alg: 'RS256'}
}
function privkeyResolver (privkeyId) {
  if (privkeyId === keyId) return {key: privateKey, passphrase: privateKeyPass, alg: 'RS256'}
}

describe('jwt.handler', function () {
  describe('extractKeyId', function () {
    const jwtHandler = JwtHandler(debugNamePrefix, pubkeyResolver, privkeyResolver)
    it('should return the correct key id from the given JWT', function (done) {
      const jwtRaw = generateJwt(keyId, tokenBody)
      expect(
        jwtHandler.extractKeyId(jwtRaw)
      ).to.eventually.equal(keyId).notify(done)
    })
    it('should raise a MissingKeyIdError if the JWT does not contain a kid property in the header', function (done) {
      const jwtRaw = generateJwt(null, tokenBody)
      expect(
        jwtHandler.extractKeyId(jwtRaw)
      ).to.eventually.rejectedWith(jwt.MissingKeyIdError).notify(done)
    })
  })
  describe('verify', function () {
    const jwtHandler = JwtHandler(debugNamePrefix, pubkeyResolver, privkeyResolver)
    it('should return the JWT body if passed a valid JWT', function (done) {
      const jwtRaw = generateJwt(keyId, tokenBody)
      expect(
        jwtHandler.verify(jwtRaw)
      ).to.eventually.deep.equal(tokenBody).notify(done)
    })
    it('should return the JWT body if passed a valid JWT and validation options that matches the JWT', function (done) {
      const jwtRaw = generateJwt(keyId, tokenBody)
      expect(
        jwtHandler.verify(jwtRaw, {issuer: tokenBody.iss})
      ).to.eventually.deep.equal(tokenBody).notify(done)
    })
    it('should raise a JsonWebTokenError if the validation options do not match', function (done) {
      const jwtRaw = generateJwt(keyId, tokenBody)
      expect(
        jwtHandler.verify(jwtRaw, {issuer: 'expected_issuer'})
      ).to.eventually.rejectedWith(jwt.JsonWebTokenError).notify(done)
    })
    it('should raise a TokenExpiredError if the JWT is already expired', function (done) {
      const tokenBody = {
        iat: Math.floor(Date.now() / 1000),
        dummy: 'dummy',
        exp: Math.floor(Date.now() / 1000) - 5000
      }
      const jwtRaw = generateJwt(keyId, tokenBody)
      expect(
        jwtHandler.verify(jwtRaw)
      ).to.eventually.rejectedWith(jwt.TokenExpiredError).notify(done)
    })
    it('should raise a NotBeforeError if the is not yet valid', function (done) {
      const tokenBody = {
        iat: Math.floor(Date.now() / 1000),
        dummy: 'dummy',
        nbf: Math.floor(Date.now() / 1000) + 1000
      }
      const jwtRaw = generateJwt(keyId, tokenBody)
      expect(
        jwtHandler.verify(jwtRaw)
      ).to.eventually.rejectedWith(jwt.NotBeforError).notify(done)
    })
    it('should raise an Error if the JWT is empty', function (done) {
      expect(
         jwtHandler.verify('')
      ).to.be.rejectedWith(jwt.JsonWebTokenError).notify(done)
    })
    it('should raise an Error if the JWT is null', function (done) {
      expect(
         jwtHandler.verify(null)
      ).to.be.rejectedWith(jwt.JsonWebTokenError).notify(done)
    })
    it('should raise an Error if the JWT is undefined', function (done) {
      expect(
         jwtHandler.verify(undefined)
      ).to.be.rejectedWith(jwt.JsonWebTokenError).notify(done)
    })
    it('should raise a MissingKeyIdError if the JWT does not contain a kid property in the header', function (done) {
      const jwtRaw = generateJwt(null, tokenBody)
      expect(
        jwtHandler.verify(jwtRaw)
      ).to.eventually.rejectedWith(jwt.MissingKeyIdError).notify(done)
    })
    it('should raise a UnknownKeyIdError if the key id is unknown', function (done) {
      const jwtRaw = generateJwt('unknown-key-id', tokenBody)
      expect(
        jwtHandler.verify(jwtRaw)
      ).to.eventually.rejectedWith(jwt.UnknownKeyIdError).notify(done)
    })
  })
  describe('create', function () {
    const jwtHandler = JwtHandler(debugNamePrefix, pubkeyResolver, privkeyResolver)
    it('should create a valid JWT if called with a key id that exists', function (done) {
      jwtHandler.create(tokenBody, keyId)
                .then(result => {
                  expect(result.match(/^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/)).to.be.instanceof(Array)
                  done()
                })
    })
    it('should raise an UnknownKeyId with a key id that does not exist', function (done) {
      const keyId = 'unknown-key-id'
      expect(
        jwtHandler.create(tokenBody, keyId)
      ).to.be.rejectedWith(jwt.UnknownKeyIdError).notify(done)
    })
    it('should raise an UnknownKeyId with an undefined key id', function (done) {
      expect(
        jwtHandler.create(tokenBody)
      ).to.be.rejectedWith(jwt.UnknownKeyIdError).notify(done)
    })
  })
})

function generateJwt (keyId, tokenBody) {
  const header = keyId ? {kid: keyId} : undefined
  return jsonwebtoken.sign(tokenBody, {
    'key': privateKey, 'passphrase': privateKeyPass}, {algorithm: 'RS256', header}
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

const privateKeyPass = 'test'
