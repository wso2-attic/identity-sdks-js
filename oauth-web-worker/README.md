# OAuth Web Worker

## What is it?

This library lets you authenticate using the OAuth 2.0 protocol with an Identity Provider.

## How does it differ from other libraries?

Here, we store the access token in a web worker. This way, we make sure that the access token cannot be accessed by malicious third-party codes.

## How does it work?

When initialized, the library creates a web worker. This web worker stores all the sensitive information such as teh access token, refresh token etc. The library then provides an interface for applications to interact with the web worker.

Once you go through the authentication flow and the token is obtained from the identity provider, the token never leaves the web worker. When access token is required to access an API endpoint of the identity provider, the API call is actually proxied through the web worker.

## How do I use this?

The library exposes a singleton class called `OAuth`. Get an instance of the `OAuth` class by calling its `getInstance()` method.

```javascript
var oAuth = Wso2OAuth.OAuth.getInstance();
```

Then, initialize the instance by passing the config parameters.

```javascript
oAuth
	.initialize({
		clientHost: "https://localhost:9443/worker",
		clientID: "70gph7I55ioGi5FqhLPz8JvxZCEa",
		serverOrigin: "https://localhost:9443",
		baseUrls: ["https://localhost:9443"],
		origin: origin,
		callbackURL: "https://localhost:9443/worker",
		enablePKCE: true,
		scope: ["SYSTEM", "openid"]
	})
	.then((response) => {
		console.log(response);
	})
	.catch((error) => {
		console.log(error);
	});
```

The following is the configuration object that is passed into the initialize method.

```typescript
export interface ConfigInterface {
	authorizationType?: string;
	clientHost: string;
	clientID: string;
	clientSecret?: string;
	consentDenied?: boolean;
	enablePKCE?: boolean;
	prompt?: string;
	responseMode?: ResponseModeTypes;
	scope?: string[];
	serverOrigin: string;
	baseUrls: string[];
	callbackURL: string;
}
```

Once initialized, you can sign in by calling the `signIn()` method.

```javascript
oAuth
	.signIn()
	.then((response) => {
		console.log(response);
	})
	.catch((error) => {
		console.error(error);
	});
```

The `signIn()` method listens to the authorization code by itself. But if the component rendered by the callback URL is different to the sign-in component, use the `listenForAuthCode()` method to capture the authorization code and continue with the authentication flow.

```javascript
oAuth
	.listenForAuthCode()
	.then((response) => console.log(response))
	.catch((error) => console.log(error));
```

To sign out,

```javascript
oAuth
	.signOut()
	.then((response) => {
		console.log(response);
	})
	.catch((error) => console.log(error));
```

To make an API call,

```javascript
const requestConfig = {
	headers: {
		"Access-Control-Allow-Origin": origin,
		"Content-Type": "application/json"
	},
	method: "GET",
	url: "https://localhost:9443/scim2/Me"
};

oAuth
	.httpRequest(requestConfig)
	.then((response) => {
		console.log(response);
	})
	.catch((error) => {
		console.log(error);
	});
```

To make multiple api calls at once (this is similar to `axios.all` or `Promise.all`),

```javascript
const headers = {
	Accept: "application/json",
	"Access-Control-Allow-Origin": store.getState().config.deployment.clientHost
};

const getQuestions = (): any => {
	return {
		headers,
		method: HttpMethods.GET,
		url: store.getState().config.endpoints.challenges
	};
};

const getAnswers = (): any => {
	return {
		headers,
		method: HttpMethods.GET,
		url: store.getState().config.endpoints.challengeAnswers
	};
};

return httpRequestAll([getQuestions(), getAnswers()]).then(([questions, answers]) => {
	return Promise.resolve([questions.data, answers.data]);
});
```

The library also supports custom grants.

```javascript
oAuth
	.customGrant({
		data: {
			grant_type: "account_switch",
			username: "user",
			"userstore-domain": "PRIMARY",
			"tenant-domain": "carbon.super",
			token: "{{token}}",
			scope: "{{scope}}",
			client_id: "{{clientId}}"
		},
		signInRequired: true,
		attachToken: false,
		returnsSession: true,
		returnResponse: false
	})
	.then((response) => {
		console.log(response);
	})
	.catch((error) => {
		console.log(error);
	});
```

The `customGrant()` methods takes a config object that has the following attributes as the argument.

```typescript
export interface CustomGrantRequestParams {
	data: any; //data to be send to the token endpoint
	signInRequired: boolean; //specifies if the grant requires the client to have been already authenticated
	attachToken: boolean; //If set to true, the request will have the token sent with the Authorization header field.
	returnsSession: boolean; //If set to true, the library will obtain the authentication session information from the response and store it in the web worker
	returnResponse: boolean; //If set to true, the response will be returned to the user
}
```
