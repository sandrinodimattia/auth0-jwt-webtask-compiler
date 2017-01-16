const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const jwksClients = { };

const validateToken = function(ctx, headers, cb) {
  try {
    if (!ctx.secrets.AUTH0_DOMAIN || ctx.secrets.AUTH0_DOMAIN === '') {
      return cb({
        status: 500,
        error: 'InternalServerError',
        error_description: 'The AUTH0_DOMAIN setting is missing.'
      });
    }

    if (!ctx.secrets.AUTH0_AUDIENCE || ctx.secrets.AUTH0_AUDIENCE === '') {
      return cb({
        status: 500,
        error: 'InternalServerError',
        error_description: 'The AUTH0_AUDIENCE setting is missing.'
      });
    }

    if (!headers || !headers.authorization || headers.authorization === '') {
      return cb({
        status: 401,
        error: 'UnauthorizedError',
        error_description: 'Authorization header is missing.'
      });
    }

    var authorizationHeader = headers.authorization.split(' ');
    if (authorizationHeader.length !== 2 || authorizationHeader[0] !== 'Bearer') {
      return cb({
        status: 401,
        error: 'UnauthorizedError',
        error_description: 'Authorization header is invalid.'
      });
    }

    var client = jwksClients[ctx.secrets.AUTH0_DOMAIN];
    if (!client) {
      client = jwksClient({
        cache: true,
        jwksUri: 'https://' + ctx.secrets.AUTH0_DOMAIN + '/.well-known/jwks.json'
      });
      jwksClients[ctx.secrets.AUTH0_DOMAIN] = client;
    }

    var token = authorizationHeader[1];
    var decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      return cb({
        status: 401,
        error: 'UnauthorizedError',
        error_description: 'Invalid token.'
      });
    }

    if (!decoded.header || decoded.header.alg !== 'RS256') {
      return cb({
        status: 401,
        error: 'UnauthorizedError',
        error_description: 'Only tokens signed using RS256 are supported.'
      });
    }

    if (!decoded.header.kid || decoded.header.kid.length === 0) {
      return cb({
        status: 401,
        error: 'UnauthorizedError',
        error_description: 'Token is missing the \'kid\' attribute.'
      });
    }

    return client.getSigningKey(decoded.header.kid, (err, key) => {
      if (err) {
        return cb({
          status: 401,
          error: 'UnauthorizedError',
          error_description: err.message
        });
      }

      var validationOptions = {
        audience: ctx.secrets.AUTH0_AUDIENCE,
        issuer: 'https://' + ctx.secrets.AUTH0_DOMAIN + '/'
      };
      jwt.verify(token, key.publicKey || key.rsaPublicKey, validationOptions, function(err, decoded) {
        if (err) {
          return cb({
            status: 401,
            error: 'UnauthorizedError',
            error_description: err.message
          });
        }

        return cb(null, decoded);
      });
    });
  } catch (e) {
    return cb({
      status: 500,
      error: 'InternalServerError',
      error_description: e.message
    });
  }
};

module.exports = function (options, cb) {
  options.nodejsCompiler(options.script, function (error, compiledFunc) {
    if (error) {
      return cb(error);
    }

    var func = compiledFunc;
    if (func.length === 3) {
      func = function(ctx, req, res) {
        validateToken(ctx, req.headers, function(err, user) {
          if (err) {
            res.writeHead(err.status, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(err, null, 2));
            return;
          }

          ctx.user = user;
          req.user = user;
          compiledFunc(ctx, req, res);
        });
      };
    } else if (func.length === 2) {
      func = function(ctx, callback) {
        validateToken(ctx, ctx.headers, function(err, user) {
          if (err) {
            return callback(err.error + ': ' + err.error_description);
          }

          ctx.user = user;
          compiledFunc(ctx, callback);
        });
      };
    } else {
      cb(new Error('Signature not compatible.'));
    }

    return cb(null, func);
  });
};
