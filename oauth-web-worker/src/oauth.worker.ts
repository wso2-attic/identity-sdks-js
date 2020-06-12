/**
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import {
	ConfigInterface,
	ResponseModeTypes,
	TokenResponseInterface,
	TokenRequestHeader,
	AuthenticatedUserInterface,
	SignInResponse,
	MessageType,
	AccountSwitchRequestParams,
	OAuthWorkerInterface,
	OAuthWorkerSingletonInterface,
} from "./models";
import {
	INIT,
	SIGN_IN,
	SERVICE_RESOURCES,
	SIGNED_IN,
	AUTH_REQUIRED,
	AUTH_CODE,
	API_CALL,
	LOGOUT,
	SWITCH_ACCOUNTS,
} from "./constants";
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from "axios";
import { getJWKForTheIdToken, isValidIdToken, getCodeVerifier, getCodeChallenge } from "./utils";
import { OIDC_SCOPE } from "./constants/token";

const OAuthWorker: OAuthWorkerSingletonInterface = (function (): OAuthWorkerSingletonInterface {
	/**
	 * Values to be set when initializing the library.
	 */
	let authorizationType: string;
	let callbackURL: string;
	let clientHost: string;
	let clientID: string;
	let clientSecret: string;
	let consentDenied: boolean;
	let enablePKCE: boolean;
	let prompt: string;
	let responseMode: ResponseModeTypes;
	let requestedScope: string[];
	let serverOrigin: string;
	let tenant: string;
	let tenantPath: string;
	let baseUrls: string[];

	/**
	 * Set after querying the IdP for oidc endpoints.
	 */
	let isOpConfigInitiated: boolean;
	let authorizeEndpoint: string;
	let tokenEndpoint: string;
	let endSessionEndpoint: string;
	let jwksUri: string;
	let revokeTokenEndpoint: string;
	let issuer: string;

	let authorizationCode: string;
	let pkceCodeVerifier: string;

	/**
	 * Set after successful authentication.
	 */
	let token: string;
	let accessTokenExpiresIn: string;
	let accessTokenIssuedAt: string;
	let displayName: string;
	let email: string;
	let idToken: string;
	let refreshToken: string;
	let tokenType: string;
	let userName: string;
	let allowedScope: string;

	let httpClient: AxiosInstance;

	let refreshTimer: number;

	let instance: OAuthWorkerInterface;

	/**
	 * @private
	 *
	 * Gets a new access token using the `refresh-token` grant.
	 *
	 * @returns {Promise<TokenResponseInterface>} Promise that resolves with the token response.
	 */
	const sendRefreshTokenRequest = (): Promise<TokenResponseInterface> => {
		if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
			return Promise.reject("Invalid token endpoint found.");
		}

		const body = [];
		body.push(`client_id=${clientID}`);
		body.push(`refresh_token=${refreshToken}`);
		body.push("grant_type=refresh_token");

		return axios
			.post(tokenEndpoint, body.join("&"), { headers: getTokenRequestHeaders(clientHost) })
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the refresh token response: " + response.status)
					);
				}

				return validateIdToken(clientID, response.data.id_token, serverOrigin).then((valid) => {
					if (valid) {
						const tokenResponse: TokenResponseInterface = {
							accessToken: response.data.access_token,
							expiresIn: response.data.expires_in,
							idToken: response.data.id_token,
							refreshToken: response.data.refresh_token,
							scope: response.data.scope,
							tokenType: response.data.token_type,
						};

						return Promise.resolve(tokenResponse);
					}
					return Promise.reject(
						new Error("Invalid id_token in the token response: " + response.data.id_token)
					);
				});
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	};

	/**
	 * @private
	 *
	 * Revokes the access token so that the user is effectively logged out.
	 *
	 * @returns {Promise<any>} A promise that resolves when signing out is successful.
	 */
	const sendRevokeTokenRequest = (): Promise<any> => {
		if (!revokeTokenEndpoint || revokeTokenEndpoint.trim().length === 0) {
			return Promise.reject("Invalid revoke token endpoint found.");
		}

		const body = [];
		body.push(`client_id=${clientID}`);
		body.push(`token=${token}`);
		body.push("token_type_hint=access_token");

		return axios
			.post(revokeTokenEndpoint, body.join("&"), {
				headers: getTokenRequestHeaders(clientHost),
				withCredentials: true,
			})
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the revoke token response: " + response.status)
					);
				}

				destroyUserSession();
				return Promise.resolve(response);
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	};

	/**
	 * @private
	 *
	 * Allows switching user accounts.
	 *
	 * @param {AccountSwitchRequestParams} requestParams Contains the username,
	 * userstore domain and tenant domain information.
	 *
	 * @returns {Promise<TokenResponseInterface>} A promise that resolves with the access token, ID token, etc.
	 */
	const sendAccountSwitchRequest = (requestParams: AccountSwitchRequestParams): Promise<TokenResponseInterface> => {
		if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
			return Promise.reject(new Error("Invalid token endpoint found."));
		}

		let scope = OIDC_SCOPE;

		if (requestedScope && requestedScope.length > 0) {
			if (!requestedScope.includes(OIDC_SCOPE)) {
				requestedScope.push(OIDC_SCOPE);
			}
			scope = requestedScope.join(" ");
		}

		const body = [];
		body.push("grant_type=account_switch");
		body.push(`username=${requestParams.username}`);
		body.push(`userstore-domain=${requestParams["userstore-domain"]}`);
		body.push(`tenant-domain=${requestParams["tenant-domain"]}`);
		body.push(`token=${token}`);
		body.push(`scope=${scope}`);
		body.push(`client_id=${clientID}`);

		return axios
			.post(tokenEndpoint, body.join("&"), { headers: getTokenRequestHeaders(clientHost) })
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the token response: " + response.status)
					);
				}

				return validateIdToken(clientID, response.data.id_token, serverOrigin).then((valid) => {
					if (valid) {
						const tokenResponse: TokenResponseInterface = {
							accessToken: response.data.access_token,
							expiresIn: response.data.expires_in,
							idToken: response.data.id_token,
							refreshToken: response.data.refresh_token,
							scope: response.data.scope,
							tokenType: response.data.token_type,
						};
						return Promise.resolve(tokenResponse);
					}

					return Promise.reject(
						new Error("Invalid id_token in the token response: " + response.data.id_token)
					);
				});
			})
			.catch((error) => {
				return Promise.reject(error);
			});
	};

	/**
	 * @private
	 *
	 * Returns the http header to be sent when requesting tokens.
	 *
	 * @param {string} clientHost The client host.
	 *
	 * @returns {TokenRequestHeader} The token request header.
	 */
	const getTokenRequestHeaders = (clientHost: string): TokenRequestHeader => {
		return {
			Accept: "application/json",
			"Access-Control-Allow-Origin": clientHost,
			"Content-Type": "application/x-www-form-urlencoded",
		};
	};

	/**
	 * @private
	 *
	 * Checks the validity of the ID token.
	 *
	 * @param {string} clientID The client ID.
	 * @param {string} idToken The ID token.
	 * @param {string} serverOrigin The server origin.
	 *
	 * @returns {Promise<boolean>} A promise that resolves with the validity status of the ID token.
	 */
	const validateIdToken = (clientID: string, idToken: string, serverOrigin: string): Promise<boolean> => {
		const jwksEndpoint = jwksUri;

		if (!jwksEndpoint || jwksEndpoint.trim().length === 0) {
			return Promise.reject("Invalid JWKS URI found.");
		}
		return axios
			.get(jwksEndpoint)
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(new Error("Failed to load public keys from JWKS URI: " + jwksEndpoint));
				}

				const jwk = getJWKForTheIdToken(idToken.split(".")[0], response.data.keys);

				if (!issuer || issuer.trim().length === 0) {
					issuer = serverOrigin + SERVICE_RESOURCES.token;
				}

				const validity = isValidIdToken(idToken, jwk, clientID, issuer, getAuthenticatedUser(idToken).username);

				return Promise.resolve(validity);
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	};

	/**
	 * @private
	 *
	 * Returns the authenticated user's information.
	 *
	 * @param {string} idToken ID token.
	 *
	 * @returns {AuthenticatedUserInterface} User information.
	 */
	const getAuthenticatedUser = (idToken: string): AuthenticatedUserInterface => {
		const payload = JSON.parse(atob(idToken.split(".")[1]));
		const emailAddress = payload.email ? payload.email : null;

		return {
			displayName: payload.preferred_username ? payload.preferred_username : payload.sub,
			email: emailAddress,
			username: payload.sub,
		};
	};

	/**
	 * @private
	 *
	 * Initializes user session.
	 *
	 * @param {TokenResponseInterface} tokenResponse The response obtained by querying the `token` endpoint.
	 * @param {AuthenticatedUserInterface} authenticatedUser User information.
	 */
	const initUserSession = (
		tokenResponse: TokenResponseInterface,
		authenticatedUser: AuthenticatedUserInterface
	): void => {
		token = tokenResponse.accessToken;
		accessTokenExpiresIn = tokenResponse.expiresIn;
		accessTokenIssuedAt = (Date.now() / 1000).toString();
		displayName = authenticatedUser.displayName;
		email = authenticatedUser.email;
		idToken = tokenResponse.idToken;
		allowedScope = tokenResponse.scope;
		refreshToken = tokenResponse.refreshToken;
		tokenType = tokenResponse.tokenType;
		userName = authenticatedUser.username;

		refreshTimer = setTimeout(() => {
			refreshAccessToken()
				.then((response) => {})
				.catch((error) => {
					console.error(error?.response);
				});
		}, (parseInt(accessTokenExpiresIn) - 10) * 1000);
	};

	/**
	 * @private
	 *
	 * Destroys user session.
	 */
	const destroyUserSession = (): void => {
		token = null;
		accessTokenExpiresIn = null;
		accessTokenIssuedAt = null;
		displayName = null;
		email = null;
		idToken = null;
		allowedScope = null;
		refreshToken = null;
		tokenType = null;
		userName = null;

		clearTimeout(refreshTimer);
		refreshTimer = null;
	};

	/**
	 * @private
	 *
	 * Requests the `token` endpoint for an access token.
	 *
	 * @returns {Promise<TokenResponseInterface>} A promise that resolves with the token response.
	 */
	const sendTokenRequest = (): Promise<TokenResponseInterface> => {
		if (!tokenEndpoint || tokenEndpoint.trim().length === 0) {
			return Promise.reject(new Error("Invalid token endpoint found."));
		}

		const body = [];
		body.push(`client_id=${clientID}`);

		if (clientSecret && clientSecret.trim().length > 0) {
			body.push(`client_secret=${clientSecret}`);
		}

		const code = authorizationCode;
		authorizationCode = null;
		body.push(`code=${code}`);

		body.push("grant_type=authorization_code");
		body.push(`redirect_uri=${callbackURL}`);

		if (enablePKCE) {
			body.push(`code_verifier=${pkceCodeVerifier}`);
			pkceCodeVerifier = null;
		}

		return axios
			.post(tokenEndpoint, body.join("&"), { headers: getTokenRequestHeaders(clientHost) })
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error("Invalid status code received in the token response: " + response.status)
					);
				}
				return validateIdToken(clientID, response.data.id_token, serverOrigin).then((valid) => {
					if (valid) {
						const tokenResponse: TokenResponseInterface = {
							accessToken: response.data.access_token,
							expiresIn: response.data.expires_in,
							idToken: response.data.id_token,
							refreshToken: response.data.refresh_token,
							scope: response.data.scope,
							tokenType: response.data.token_type,
						};

						return Promise.resolve(tokenResponse);
					}

					return Promise.reject(
						new Error("Invalid id_token in the token response: " + response.data.id_token)
					);
				});
			})
			.catch((error) => {
				return Promise.reject(error.response);
			});
	};

	/**
	 * Sets if the OpenID configuration has been initiated or not.
	 *
	 * @param {boolean} status Status to set.
	 */
	const setIsOpConfigInitiated = (status: boolean) => {
		isOpConfigInitiated = status;
	};

	/**
	 * Returns if the user has signed in or not.
	 *
	 * @returns {boolean} Signed in or not.
	 */
	const isSignedIn = (): boolean => {
		return !!token;
	};

	/**
	 * Checks if an access token exists.
	 *
	 * @returns {boolean} If the access token exists or not.
	 */
	const doesTokenExist = (): boolean => {
		if (token) {
			return true;
		}

		return false;
	};

	/**
	 * Sets the authorization code.
	 *
	 * @param {string} authCode The authorization code.
	 */
	const setAuthorizationCode = (authCode: string) => {
		authorizationCode = authCode;
	};

	/**
	 * Queries the OpenID endpoint to get the necessary API endpoints.
	 *
	 * @param {boolean} forceInit Determines if a OpenID-configuration initiation should be forced.
	 *
	 * @returns {Promise<any>} A promise that resolves with the endpoint data.
	 */
	const initOPConfiguration = (forceInit?: boolean): Promise<any> => {
		if (!forceInit && isOpConfigInitiated) {
			return Promise.resolve();
		}

		return axios
			.get(serverOrigin + tenant + SERVICE_RESOURCES.wellKnown)
			.then((response) => {
				if (response.status !== 200) {
					return Promise.reject(
						new Error(
							"Failed to load OpenID provider configuration from: " +
								serverOrigin +
								tenant +
								SERVICE_RESOURCES.wellKnown
						)
					);
				}

				authorizeEndpoint = response.data.authorization_endpoint;
				tokenEndpoint = response.data.token_endpoint;
				endSessionEndpoint = response.data.end_session_endpoint;
				jwksUri = response.data.jwks_uri;
				revokeTokenEndpoint =
					response.data.token_endpoint.substring(0, response.data.token_endpoint.lastIndexOf("token")) +
					"revoke";
				issuer = response.data.issuer;
				setIsOpConfigInitiated(true);

				return Promise.resolve(
					"Initialized OpenID Provider configuration from: " +
						serverOrigin +
						tenant +
						SERVICE_RESOURCES.wellKnown
				);
			})
			.catch(() => {
				authorizeEndpoint = serverOrigin + SERVICE_RESOURCES.authorize;
				tokenEndpoint = serverOrigin + SERVICE_RESOURCES.token;
				revokeTokenEndpoint = serverOrigin + SERVICE_RESOURCES.revoke;
				endSessionEndpoint = serverOrigin + SERVICE_RESOURCES.logout;
				jwksUri = serverOrigin + tenant + SERVICE_RESOURCES.jwks;
				issuer = serverOrigin + SERVICE_RESOURCES.token;
				tenant = tenant;
				setIsOpConfigInitiated(true);

				return Promise.resolve(
					new Error(
						"Initialized OpenID Provider configuration from default configuration." +
							"Because failed to access wellknown endpoint: " +
							serverOrigin +
							tenant +
							SERVICE_RESOURCES.wellKnown
					)
				);
			});
	};

	/**
	 * Sets the PKCE code.
	 *
	 * @param {string} pkce The PKCE code.
	 */
	const setPkceCodeVerifier = (pkce: string) => {
		pkceCodeVerifier = pkce;
	};

	/**
	 * Generates and returns the authorization code request URL.
	 *
	 * @returns {string} The authorization code request URL.
	 */
	const generateAuthorizationCodeRequestURL = (): string => {
		if (!authorizeEndpoint || authorizeEndpoint.trim().length === 0) {
			throw new Error("Invalid authorize endpoint found.");
		}

		let authorizeRequest = authorizeEndpoint + "?response_type=code&client_id=" + clientID;

		let scope = OIDC_SCOPE;

		if (requestedScope && requestedScope.length > 0) {
			if (!requestedScope.includes(OIDC_SCOPE)) {
				requestedScope.push(OIDC_SCOPE);
			}
			scope = requestedScope.join(" ");
		}

		authorizeRequest += "&scope=" + scope;
		authorizeRequest += "&redirect_uri=" + callbackURL;

		if (responseMode) {
			authorizeRequest += "&response_mode=" + responseMode;
		}

		if (enablePKCE) {
			const codeVerifier = getCodeVerifier();
			const codeChallenge = getCodeChallenge(codeVerifier);
			pkceCodeVerifier = codeVerifier;
			authorizeRequest += "&code_challenge_method=S256&code_challenge=" + codeChallenge;
		}

		if (prompt) {
			authorizeRequest += "&prompt=" + prompt;
		}

		return authorizeRequest;
	};

	/**
	 * Sends a sign in request.
	 * 
	 * @returns {Promise<SignInResponse>} A promise that resolves with the Sign In response.
	 */
	const sendSignInRequest = (): Promise<SignInResponse> => {
		if (authorizationCode) {
			return sendTokenRequest()
				.then((response: TokenResponseInterface) => {
					try {
						initUserSession(response, getAuthenticatedUser(response.idToken));
					} catch (error) {
						throw Error(error);
					}
					return Promise.resolve({ type: SIGNED_IN } as SignInResponse);
				})
				.catch((error) => {
					if (error.response && error.response.status === 400) {
						return Promise.resolve({
							type: AUTH_REQUIRED,
							code: generateAuthorizationCodeRequestURL(),
							pkce: pkceCodeVerifier,
						});
					}

					return Promise.reject(error);
				});
		} else {
			return Promise.resolve({
				type: AUTH_REQUIRED,
				code: generateAuthorizationCodeRequestURL(),
				pkce: pkceCodeVerifier,
			});
		}
	};

	/**
	 * Refreshes the token.
	 * 
	 * @returns {Promise<boolean>} A promise that resolves with `true` if refreshing is successful.
	 */
	const refreshAccessToken = (): Promise<boolean> => {
		return new Promise((resolve, reject) => {
			sendRefreshTokenRequest()
				.then((response) => {
					initUserSession(response, getAuthenticatedUser(response.idToken));
					resolve(true);
				})
				.catch((error) => {
					reject(error);
				});
		});
	};

	/**
	 * Switches accounts.
	 * 
	 * @param {AccountSwitchRequestParams} requestParams Contains the username, userstore domain and tenant domain. 
	 */
	const switchAccount = (requestParams: AccountSwitchRequestParams): Promise<boolean> => {
		return new Promise((resolve, reject) => {
			sendAccountSwitchRequest(requestParams)
				.then((response) => {
					initUserSession(response, getAuthenticatedUser(response.idToken));
					resolve(true);
				})
				.catch((error) => {
					reject(error);
				});
		});
	};

	/**
	 * Signs out.
	 * 
	 * @returns {Promise<boolean>} A promise that resolves with `true` if sign out is successful.
	 */
	const signOut = (): Promise<boolean> => {
		return new Promise((resolve, reject) => {
			sendRevokeTokenRequest()
				.then((response) => {
					resolve(true);
				})
				.catch((error) => {
					reject(error);
				});
		});
	};

	/**
	 * Makes api calls.
	 * 
	 * @param {AxiosRequestConfig} config API request data.
	 * 
	 * @returns {AxiosResponse} A promise that resolves with the response.
	 */
	const httpRequest = (config: AxiosRequestConfig): Promise<AxiosResponse> => {
		let matches = false;
		baseUrls.forEach((baseUrl) => {
			if (config.url.startsWith(baseUrl)) {
				matches = true;
			}
		});

		if (matches) {
			return httpClient(config)
				.then((response: AxiosResponse) => {
					return Promise.resolve(response);
				})
				.catch((error: AxiosError) => {
					if (error?.response?.status === 401) {
						clearTimeout(refreshTimer);
						refreshTimer = null;

						return refreshAccessToken()
							.then((response) => {
								return httpClient(config)
									.then((response) => {
										return Promise.resolve(response);
									})
									.catch((error) => {
										return Promise.reject(error?.response);
									});
							})
							.catch((error) => {
								return Promise.reject(error);
							});
					}
					return Promise.reject(error?.response);
				});
		} else {
			return Promise.reject("The provided URL is illegal.");
		}
	};

	/**
	 * @constructor
	 * 
	 * Constructor function that returns an object containing all the public methods.
	 *
	 * @param {ConfigInterface} config Configuration data.
	 * 
	 * @returns {OAuthWorkerInterface} Returns the object containing 
	 */
	function Constructor(config: ConfigInterface): OAuthWorkerInterface {
		authorizationType = config.authorizationType;
		callbackURL = config.callbackURL;
		clientHost = config.clientHost;
		clientID = config.clientID;
		clientSecret = config.clientSecret;
		consentDenied = config.consentDenied;
		enablePKCE = config.enablePKCE;
		prompt = config.prompt;
		responseMode = config.responseMode;
		requestedScope = config.scope;
		serverOrigin = config.serverOrigin;
		tenant = config.tenant ?? "";
		tenantPath = config.tenantPath;
		baseUrls = config.baseUrls;

		httpClient = axios.create({
			withCredentials: true,
		});

		httpClient.interceptors.request.use(
			(config) => {
				config.headers = {
					...config.headers,
					Authorization: `Bearer ${token}`,
				};

				return config;
			},
			(error) => {
				return Promise.reject(error);
			}
		);

		return {
			setIsOpConfigInitiated,
			isSignedIn,
			doesTokenExist,
			setAuthorizationCode,
			initOPConfiguration,
			setPkceCodeVerifier,
			generateAuthorizationCodeRequestURL,
			sendSignInRequest,
			refreshAccessToken,
			switchAccount,
			signOut,
			httpRequest,
		};
	}

	return {
		getInstance: (config: ConfigInterface): OAuthWorkerInterface => {
			if (instance) {
				return instance;
			} else {
				instance = Constructor(config);
				return instance;
			}
		},
	};
})();

let oAuthWorker: OAuthWorkerInterface;

onmessage = ({ data, ports }: { data: { type: MessageType; data: any }; ports: readonly MessagePort[] }) => {
	const port = ports[0];

	switch (data.type) {
		case INIT:
			try {
				oAuthWorker = OAuthWorker.getInstance(data.data);
				port.postMessage({ success: true });
			} catch (error) {
				port.postMessage({ success: false, error: error });
			}
			break;
		case SIGN_IN:
			if (!oAuthWorker) {
				port.postMessage({ success: false, error: "Worker has not been initiated." });
			} else if (oAuthWorker.doesTokenExist()) {
				port.postMessage({ success: true, data: { type: SIGNED_IN } });
			} else {
				oAuthWorker
					.initOPConfiguration()
					.then(() => {
						oAuthWorker
							.sendSignInRequest()
							.then((response: SignInResponse) => {
								if (response.type === SIGNED_IN) {
									port.postMessage({ success: true, data: { type: SIGNED_IN } });
								} else {
									port.postMessage({
										success: true,
										data: { type: AUTH_REQUIRED, code: response.code, pkce: response.pkce },
									});
								}
							})
							.catch((error) => {
								port.postMessage({ success: false, error: error });
							});
					})
					.catch((error) => {
						port.postMessage({ success: false, error: error });
					});
			}
			break;
		case AUTH_CODE:
			if (!oAuthWorker) {
				port.postMessage({ success: false, error: "Worker has not been initiated." });
				break;
			}
			
			oAuthWorker.setAuthorizationCode(data.data.code);

			if (data.data.pkce) {
				oAuthWorker.setPkceCodeVerifier(data.data.pkce);
			}
			oAuthWorker
				.initOPConfiguration()
				.then(() => {
					oAuthWorker
						.sendSignInRequest()
						.then((response: SignInResponse) => {
							if (response.type === SIGNED_IN) {
								port.postMessage({ success: true, data: { type: SIGNED_IN } });
							} else {
								port.postMessage({
									success: true,
									data: { type: AUTH_REQUIRED, code: response.code, pkce: response.pkce },
								});
							}
						})
						.catch((error) => {
							port.postMessage({ success: false, error: error });
						});
				})
				.catch((error) => {
					port.postMessage({ success: false, error: error });
				});
			break;
		case API_CALL:
			if (!oAuthWorker) {
				port.postMessage({ success: false, error: "Worker has not been initiated." });
				break;
			}

			if (!oAuthWorker.isSignedIn()) {
				port.postMessage({ success: false, error: "You have not signed in yet." });
			} else {
				oAuthWorker
					.httpRequest(data.data)
					.then((response) => {
						port.postMessage({
							success: true,
							data: {
								data: response.data,
								status: response.status,
								statusText: response.statusText,
								headers: response.headers,
							},
						});
					})
					.catch((error) => {
						port.postMessage({ success: false, error: error });
					});
			}
			break;
		case LOGOUT:
			if (!oAuthWorker) {
				port.postMessage({ success: false, error: "Worker has not been initiated." });
				break;
			}

			if (!oAuthWorker.isSignedIn()) {
				port.postMessage({ success: false, error: "You have not signed in yet." });
			} else {
				oAuthWorker
					.signOut()
					.then((response) => {
						if (response) {
							port.postMessage({ success: true, data: true });
						} else {
							port.postMessage({ success: false, error: `Received ${response}` });
						}
					})
					.catch((error) => {
						port.postMessage({ success: false, error: error });
					});
			}
			break;
		case SWITCH_ACCOUNTS:
			if (!oAuthWorker) {
				port.postMessage({ success: false, error: "Worker has not been initiated." });
				break;
			}

			if (!oAuthWorker.isSignedIn()) {
				port.postMessage({ success: false, error: "You have not signed in yet." });
			} else {
				oAuthWorker
					.switchAccount(data.data)
					.then((response) => {
						if (response) {
							port.postMessage({ success: true, data: true });
						} else {
							port.postMessage({ success: false, error: `Received ${response}` });
						}
					})
					.catch((error) => {
						port.postMessage({ success: false, error: error });
					});
			}
			break;
		default:
			port.postMessage({ success: false, error: `Unknown message type ${data?.type}` });
	}
};
