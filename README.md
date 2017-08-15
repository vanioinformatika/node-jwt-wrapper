[![Coverage Status](https://coveralls.io/repos/github/vanioinformatika/node-jwt-wrapper/badge.svg?branch=master)](https://coveralls.io/github/vanioinformatika/node-jwt-wrapper?branch=master)
[![Build Status](https://travis-ci.org/vanioinformatika/node-jwt-wrapper.svg?branch=master)](https://travis-ci.org/vanioinformatika/node-jwt-wrapper)

# node-jwt-wrapper
A promisified wrapper around the jsonwebtoken npm module that handles key ids.
Uses native promises.

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

const jwtHandler = new jwt.JwtHandler('myproject', pubkeyResolver, privkeyResolver)

// or with options object

const jwtHandler = new jwt.JwtHandler({
    debugNamePrefix: 'myproject',
    pubkeyResolver: pubkeyResolver,
    privkeyResolver: privkeyResolver,
})

// Verifying JWT tokens
jwtHandler.verify(jwtRaw)
          .then(jwtBody => {
            ...
          })
          .catch(err => {
            // Handle errors
          })


// Creating JWT tokens
const keyId = 'keyid1'
const tokenBody = { iat: Math.floor(Date.now() / 1000), sub: 'token subject', iss: 'issuer1', aud: 'audience1' }

jwtHandler.create(tokenBody, keyId)
          .then(jwt => {
            ...
          })
          .catch(err => {
            // Handle errors
          })
...
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
