const jwt = require('jsonwebtoken')

const Handler = require('./jwt.handler')
const { MissingKeyIdError, UnknownKeyIdError } = require('./errors')

module.exports = {
  Handler,
  MissingKeyIdError,
  UnknownKeyIdError,
  TokenExpiredError: jwt.TokenExpiredError,
  NotBeforeError: jwt.NotBeforeError,
  JsonWebTokenError: jwt.JsonWebTokenError
}
