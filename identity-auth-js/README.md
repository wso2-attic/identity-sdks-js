# WSO2 Identity Server - Authentication SDK for Javascript Applications

Provide OpenID Connect (OIDC) and OAuth2 protocol support for JavaScript client applications.

---

## Getting started

### Build distrubution

Run `yarn run build`

> For development (watch mode) Run `yarn run watch`.

## Usage

### 1. Import module

Add following dependency in your package.json file.
`"@wso2is/identity-auth-js": "^0.1.0"`

### 2. Initialize client

Minimal required configuration to initialize the client

```js
/**
 * Initialize identityManager client
 */
const identityManager = new IdentityClient({
    callbackURL: "",
    clientHost: "",
    clientID: "",
    serverOrigin: ""
});
```

#### Configuration Properties

| Config                             | Type    | Description |
|---                                 |---      | --- |
| **autherizationType** _(optional)_ | string  |  |
| **callbackURL**                    | string  | Where to redirect upon successful authentication. (Note:- This should be configured in WSO2 Identity Server) E.g. https://mydomain.com/myapp/home |
| **clientHost**                     | string  | Application origin address. With tenant path if has. E.g. https://mydomain.com/myapp or https://mydomain.com/t/exmaple.com/myapp |
| **clientID**                       | string  | Application client-id generated in WSO2 Identity Server |
| **clientSecret** _(optional)_      | string  | Application client-secret generated in WSO2 Identity Server |
| **consentDenied** _(optional)_     | boolean |  |
| **enablePKCE** _(optional)_        | boolean |  |
| **prompt** _(optional)_            | string  |  |
| **responseMode** _(optional)_      | string  | "query" or "form_post"  |
| **scope** _(optional)_             | array   | { string array } |
| **serverOrigin**                   | string  | WSO2 Identity Server address. E.g. https://is.mydomain.com |
| **tenant** _(optional)_            | string  | Tenant name. (Note:- Leave it blank for super tenant) E.g. example.com |
| **tenantPath** _(optional)_        | string  | Tenant Path. (Note:- Leave it blank for super tenant) E.g /t/example.com |

### 3. Methods

#### SignIn()

```js
identityManager.signIn(
    () => {
        // Callback method upon successful authnetication
    })
    .catch((error) => {
        throw error;
    });
```

#### SignOut()

```js
identityManager.signOut(
    () => {
        // Callback method upon logout
    })
    .catch((error) => {
        throw error;
    });
```

---

## Advance methods

#### OPConfigurationUtil.initOPConfiguration(wellKnownEndpoint, forceInit)

Initiate the authentication module using openid provider configuration endpoint.
* `wellKnownEndpoint` well known endpoint.
* `forceInit` whether to re-initiate the configuration.

#### OPConfigurationUtil.resetOPConfiguration()

Reset the configuration acquired from openid provider.

#### SignInUtil.sendAuthorizationRequest(requestParams)

Sends the OAuth2 authorization code request to the IdP based on the provided request params.

`requestParams` is type of `OIDCRequestParamsInterface`

```js
interface OIDCRequestParamsInterface {
    clientID: string;
    clientHost: string;
    clientSecret?: string;
    enablePKCE: boolean;
    redirectUri: string;
    scope?: string[];
    serverOrigin: string;
}
```

* `clientID` Client id of the application.
* `clientHost` Client host name.
* `clientSecret` Client secret of the application. If not provided, it will considered as a public client.
* `enablePKCE` Enable PKCE for the authorization grant type.
* `redirectUri` Callback url of the application.

#### SignInUtil.hasAuthorizationCode()

Check whether the current url contains the OAuth2 authorization code.

#### SignInUtil.sendTokenRequest(requestParams)

Sends the OAuth2 token request and returns a Promise with token response. Also validate the signature of the id_token.

`requestParams` is type of `OIDCRequestParamsInterface` as explained above.

Response will be a `Promise<TokenResponseInterface>`.

```js
interface TokenResponseInterface {
    accessToken: string;
    idToken: string;
    expiresIn: string;
    scope: string;
    refreshToken: string;
    tokenType: string;
}
```

* `accessToken` access token.
* `idToken` id_token value.
* `expiresIn`validity period.
* `scope` scope returned.
* `refreshToken` refresh token.
* `tokenType` token type.

#### SignInUtil.getAuthenticatedUser(idToken)

This will extract the authenticated user from the id_token.

Response will be in `AuthenticatedUserInterface`.

```js
interface AuthenticatedUserInterface {
    displayName?: string;
    email?: string;
    username: string;
}
```

* `displayName` display name of the user.
* `email` email of the user.
* `username` username.

#### AuthenticateSessionUtil.initUserSession(tokenResponse, authenticatedUser)

This will initiate the user session using the attributes in tokenResponse and authenticatedUser.

tokenResponse is type of `TokenResponseInterface` and authenticatedUser is type of `AuthenticatedUserInterface`.

#### AuthenticateSessionUtil.getAccessToken()

This will returns a Promise containing the OAuth2 access_token. Also it will refresh the access_token if it is expired.

Response will be a `Promise<string>`.

#### SignOutUtil.sendSignOutRequest(redirectUri)

Sends the logout request the openid provider. Requires the redirect uri of the application.

#### AuthenticateSessionUtil.endAuthenticatedSession()

Terminates the user session and clears the session attributes.

---

## License

Licenses this source under the Apache License, Version 2.0 ([LICENSE](LICENSE)), You may not use this file except in compliance with the License.
