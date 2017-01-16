# Webtask Compiler for Auth0 access tokens

This webtask compiler will validate your Auth0 access tokens before executing your webtask. You can read more about [Webtask compilers](https://webtask.io/docs/webtask-compilers) here.

## Usage

In order to use this Webtask compiler you have to specify it when creating your webtask:

```bash
wt create hello.js \
  --meta wt-compiler=https://cdn.rawgit.com/sandrinodimattia/auth0-jwt-webtask-compiler/master/compiler.js
  --secret AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
  --secret AUTH0_AUDIENCE=YOUR_AUTH0_AUDIENCE
```

After setting up this compiler, you can send your access token to your webtask:

```bash
curl -X GET -H "Authorization: Bearer eyJ0..." -H "Content-Type: application/json" "https://you.run.webtask.io/hello"
```

The compiler will validate the signature of the token, the audience and the issuer. As a final step it will set the decoded token on `context.user` and `req.user` after which your Webtask will be executed.

## Example Webtasks

Using the simple signature:

```js
module.exports = function(ctx, cb) {
  cb(null, 'Hello ' + ctx.user.sub + '. Here are your scopes: ' + ctx.user.scope);
}
```

Using request/response:

```js
module.exports = function(ctx, req, res) {
  res.writeHead(200);
  res.end('Hello ' + req.user.sub + '. Here are your scopes: ' + req.user.scope);
}
```

## How do I get an access token from Auth0?

Start by creating an API [here](https://manage.auth0.com/#/apis). The `Identifier` you set here is the value you will use for `AUTH0_AUDIENCE` (eg: `urn:myapi`).

Then using the code flow, implicit flow, client credentials or password grant you can get an access token by setting `audience=urn:myapi` for example. The resulting access token can then be sent to your Webtask as a bearer token.
