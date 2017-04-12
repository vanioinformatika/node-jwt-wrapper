# node-jwt-wrapper
A promisified wrapper around the jsonwebtoken npm module that handles key ids.
Uses bluebird promises.

## Usage

```js
const jwt = require('@vanioinformatika/jwt-wrapper') (

/**
 * Resolves public keys or certificates can be sync or async function
 * @param {string} The key id
 */
function pubkeyResolver (keyId) {
  const cert = ... // load certificate or public key
  const alg = ... // resolve key algorithm (JWA values like RS256, ES256, etc.)
  return {cert, alg}
}

/**
 * Resolves private keys can be sync or async function
 * @param {string} The key id
 */
function privkeyResolver (keyId) {
  const key = ... // load private key in PEM format
  const passphrase = ... // load private key passphrase
  const alg = ... // resolve key algorithm (JWA values like RS256, ES256, etc.)
  return {key, passphrase, alg}
}

const jwtHandler = jwt.Handler('myproject', pubkeyResolver, privkeyResolver)

// Verifying JWT tokens
jwtHandler.verify(jwtRaw)
          .then(jwtBody => {
            ...
          })
          .catch(jwt.MissingKeyIdError, err => {
            // Handle MissingKeyIdError
          })
          .catch(jwt.UnknownKeyIdError, err => {
            // Handle UnknownKeyIdError
          })
          .catch(jwt.TokenExpiredError, err => {
            // Handle TokenExpiredError
          })
          .catch(jwt.NotBeforeError, err => {
            // Handle NotBeforeError
          })
          .catch(jwt.JsonWebTokenError, err => {
            // Handle other JWT related errors
          })
          .catch(err => {
            // Handle other errors
          })

// Creating JWT tokens
const keyId = 'keyid1'
const tokenBody = { iat: Math.floor(Date.now() / 1000), sub: 'token subject', iss: 'issuer1', aud: 'audience1' }

jwtHandler.create(tokenBody, keyId)
          .then(jwt => {
            ...
          })
          .catch(jwt.UnknownKeyIdError, err => {
            // Handle UnknownKeyIdError
          })
          .catch(err => {
            // Handle other errors
          })
...

// publishing public keys with express.js
router.route('/certs').get((req, res) => {
  const certificateList = keystore.fny.getAllCertificatesAsJWKS()
  res.status(HttpStatus.OK).json({keys: certificateList})
})
```

## Implementing key resolvers

This module can be used with either synchronous or asynchronous key resolvers. Either way, you may want to implement some kind of cache for the keys as the resolvers are called on every Handler.validate and Handler.create calls.

### Synchronous example:
```js
/** resolves public keys and certificates synchronously */
function pubkeyResolver (keyId) {
  const cert = fs.readFileSync(path.join(basedir, `cert.${keyId}.crt`))
  const alg = getKeyAlg(cert)
  if (cert) {
    return {cert, alg}
  }
}
/** resolves private keys synchronously */
function privkeyResolver (keyId) {
  const key = fs.readFileSync(path.join(basedir, `privkey.${keyId}.key`))
  if (key) {
    const alg = getKeyAlg(key)
    const passphrase = getPassphrase(keyId)
    return {key, passphrase, alg}
  }
}
```

### Asynchronous example:
```js
/** resolves public keys and certificates asynchronously */
function pubkeyResolver (keyId) {
  return new Promise(resolve, reject) {
    fs.readFile(path.join(basedir, `cert.${keyId}.crt`), (err, cert) => {
      if (!err) {
        const alg = getKeyAlg(cert)
        resolve({cert, alg})
      } else if (err.code === 'ENOENT') {
        resolve() // Note that if you resolve with undefined, it will result in UnknownKeyIdError
      } else {
        reject(err)
      }
    })
  }
}
/** resolves private keys asynchronously */
function privkeyResolver (keyId) {
  return new Promise(resolve, reject) {
    fs.readFile(path.join(basedir, `privkey.${keyId}.key`), (err, key) => {
      if (!err) {
        const alg = getKeyAlg(key)
        const passphrase = getPassphrase(keyId)
        resolve({key, passphrase, alg})
      } else if (err.code === 'ENOENT') {
        resolve() // Note that if you resolve with undefined, it will result in UnknownKeyIdError
      } else {
        reject(err)
      }
    })
  }
}
```
