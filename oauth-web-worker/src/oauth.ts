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

import { Message, ResponseMessage, SignInResponse, AuthCode } from "./models/message";
// @ts-ignore
import WorkerFile from "./oauth.worker.ts";
import { ConfigInterface } from "./models/client";
import { INIT, SIGN_IN, SIGNED_IN, AUTH_CODE, LOGOUT, SWITCH_ACCOUNTS, API_CALL, AUTH_REQUIRED } from "./constants";
import { AUTHORIZATION_CODE, PKCE_CODE_VERIFIER } from "./constants/token";
import { AccountSwitchRequestParams } from "./models";
import { AxiosRequestConfig, AxiosResponse } from "axios";
import { OAuthInterface, OAuthSingletonInterface } from "./models/oauth";

/**
 * This is a singleton class that allows authentication using the OAuth 2.0 protocol.
 *
 * - To get an instance of this class, use the `getInstance()` method.
 * - To initiate the authentication flow, follow the following procedure:
 * 	1. Initialize the object by calling the `initialize(config)` method. You will have to
 * 		pass a config object as an argument. To know more, checkout the `initialize()` method.
 * 	2. To get *the authorization code* from the callback URL and continue the authentication flow,
 * 		call the `listenForAuthCode()` method. In an SPA, this should be called in the page rendered by the
 * 		callback URL.
 * 	2. Kick off the authentication flow by calling the `signIn()` method.
 *
 * Example:
 *
 * ```
 * 	var oAuth = Wso2OAuth.OAuth.getInstance();
 * 		oAuth.initialize({
 * 			clientHost: "https://localhost:9443/",
 * 			clientID: "70gph7I55ioGi5FqhLPz8JvxZCEa",
 * 			serverOrigin: "https://localhost:9443",
 * 			baseUrls: ["https://localhost:9443"],
 * 			origin: origin,
 * 			callbackURL: "https://localhost:9443/worker",
 * 			enablePKCE: true,
 * 			scope: ["SYSTEM", "openid"],
 * 		}).then(response=>{
 * 			console.log(response);
 *
 *			oAuth.listenForAuthCode().then(response=>{
 * 				console.log(response);
 * 			}).catch(error=>{
 * 				console.error(error)
 * 			});
 * 		}).catch(error=>{
 * 			console.error(error)
 * 		});
 *
 *
 * ```
 */
export const OAuth: OAuthSingletonInterface = (function (): OAuthSingletonInterface {
	/**
	 * The private member variable that holds the reference to the web worker.
	 */
	let worker: Worker;
	/**
	 * The private member variable that holds the instance of this class.
	 */
	let instance: OAuthInterface;
	/**
	 * The private boolean member variable that specifies if the `initialize()` method has been called or not.
	 */
	let initialized: boolean = false;
	/**
	 * The private boolean member variable that specifies if the user is signed in or not.
	 */
	let signedIn: boolean = false;

	/**
	 * @private
	 *
	 * Extracts the authorization code from the URL and returns it.
	 *
	 * @returns {string} The authorization code.
	 *
	 */
	const getAuthorizationCode = (): string => {
		if (new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE)) {
			return new URL(window.location.href).searchParams.get(AUTHORIZATION_CODE);
		}

		return null;
	};

	/**
	 * @private
	 *
	 * @returns {string} Removes the path parameters and returns the URL.
	 *
	 * Example:
	 * `https://localhost:9443?code=g43dhkj243wghdgwedew65&session=34khkg2g`
	 * will be stripped to `https://localhost:9443`
	 */
	const removeAuthorizationCode = (): string => {
		const url = location.href;
		return url.replace(/\?code=.*$/, "");
	};

	/**
	 * @private
	 *
	 * Checks if the authorization code is present in the URL or not.
	 *
	 * @returns {boolean} Authorization code presence status.
	 */
	const hasAuthorizationCode = (): boolean => {
		return !!getAuthorizationCode();
	};

	/**
	 * @private
	 *
	 * Sends a message to the web worker and returns the response.
	 *
	 * T - Request data type.
	 *
	 * R - response data type.
	 *
	 * @param {Message} message - The message object
	 * @param {number} timeout The number seconds to wait before timing the request out. - optional
	 *
	 * @returns {Promise<R>} A promise that resolves with the obtained data.
	 */
	const communicate = <T, R>(message: Message<T>, timeout?: number): Promise<R> => {
		const channel = new MessageChannel();

		worker.postMessage(message, [channel.port2]);

		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				reject("Operation timed out");
			}, timeout ?? 5000);

			return (channel.port1.onmessage = ({ data }: { data: ResponseMessage<R> }) => {
				clearTimeout(timer);
				data.success ? resolve(data.data) : reject(data.error);
			});
		});
	};

	/**
	 * @constructor
	 * 
	 * This returns the object containing the public methods.
	 *
	 * @returns {OAuthInterface} OAuthInterface object
	 */
	function Constructor(): OAuthInterface {
		worker = new WorkerFile();

		return {
			/**
			 * Listens for the authorization code in the callback URL.
			 * If present, this will continue with the authentication flow and resolve if successfully authenticated.
			 * @returns {Promise<boolean>} Promise that resolves on successful authentication.
			 */
			listenForAuthCode: (): Promise<boolean> => {
				if (!initialized) {
					return Promise.reject(
						"Error while listening to authorization code. The object has not been initialized yet."
					);
				}
				if (hasAuthorizationCode()) {
					const authCode = getAuthorizationCode();
					const message: Message<AuthCode> = {
						type: AUTH_CODE,
						data: {
							code: authCode,
							pkce: sessionStorage.getItem(PKCE_CODE_VERIFIER),
						},
					};

					history.pushState({}, document.title, removeAuthorizationCode());

					sessionStorage.removeItem(PKCE_CODE_VERIFIER);

					return communicate<AuthCode, SignInResponse>(message)
						.then((response) => {
							if (response.type === SIGNED_IN) {
								signedIn = true;
								return Promise.resolve(true);
							}

							return Promise.reject(
								"Something went wrong during authentication. " +
									"Failed during signing in after getting the authorization code."
							);
						})
						.catch((error) => {
							return Promise.reject(error);
						});
				} else {
					return Promise.reject("No Authorization Code found.");
				}
			},

			/**
			 * Initializes the object with authentication parameters.
			 *
			 * @param {ConfigInterface} config The configuration object.
			 *
			 * @returns {Promise<boolean>} Promise that resolves when initialization is successful.
			 *
			 * The `config` object has the following attributes:
			 * ```
			 * 	var config = {
			 * 		authorizationType?: string //optional
			 * 		clientHost: string
			 * 		clientID: string
			 *  	clientSecret?: string //optional
			 * 		consentDenied?: boolean //optional
			 * 		enablePKCE?: boolean //optional
			 *		prompt?: string //optional
			 *		responseMode?: "query" | "form-post" //optional
			 *		scope?: string[] //optional
			 *		serverOrigin: string
			 *		tenant?: string //optional
			 *		tenantPath?: string //optional
			 *		baseUrls: string[]
			 *		callbackURL: string
			 *	}
			 * ```
			 */
			initialize: (config: ConfigInterface) => {
				if (config.authorizationType && typeof config.authorizationType !== "string") {
					return Promise.reject("The authorizationType must be a string");
				}
				if (!(config.baseUrls instanceof Array)) {
					return Promise.reject("baseUrls must be an array");
				}
				if (config.baseUrls.find((baseUrl) => typeof baseUrl !== "string")) {
					return Promise.reject("Array elements of baseUrls must all be string values");
				}
				if (typeof config.callbackURL !== "string") {
					return Promise.reject("The callbackURL must be a string");
				}
				if (typeof config.clientHost !== "string") {
					return Promise.reject("The clientHost must be a string");
				}
				if (typeof config.clientID !== "string") {
					return Promise.reject("The clientID must be a string");
				}
				if (config.clientSecret && typeof config.clientSecret !== "string") {
					return Promise.reject("The clientString must be a string");
				}
				if (config.consentDenied && typeof config.consentDenied !== "boolean") {
					return Promise.reject("consentDenied must be a boolean");
				}
				if (config.enablePKCE && typeof config.enablePKCE !== "boolean") {
					return Promise.reject("enablePKCE must be a boolean");
				}
				if (config.prompt && typeof config.prompt !== "string") {
					return Promise.reject("The prompt must be a string");
				}
				if (config.responseMode && typeof config.responseMode !== "string") {
					return Promise.reject("The responseMode must be a string");
				}
				if (config.responseMode && config.responseMode !== "form_post" && config.responseMode !== "query") {
					return Promise.reject("The responseMode is invalid");
				}
				if (config.scope && !(config.scope instanceof Array)) {
					return Promise.reject("scope must be an array");
				}
				if (config.scope && config.scope.find((aScope) => typeof aScope !== "string")) {
					return Promise.reject("Array elements of scope must all be string values");
				}
				if (typeof config.serverOrigin !== "string") {
					return Promise.reject("serverOrigin must be a string");
				}
				if (config.tenant && typeof config.tenant !== "string") {
					return Promise.reject("The tenant must be a string");
				}
				if (config.tenantPath && typeof config.tenantPath !== "string") {
					return Promise.reject("The tenantPath must be a string");
				}

				const message: Message<ConfigInterface> = {
					type: INIT,
					data: config,
				};

				return communicate<ConfigInterface, null>(message)
					.then((response) => {
						initialized = true;
						return Promise.resolve(true);
					})
					.catch((error) => {
						return Promise.reject(error);
					});
			},

			/**
			 * Initiates the authentication flow.
			 *
			 * @returns {Promise<boolean>} A promise that resolves when authentication is successful.
			 */
			signIn: (): Promise<boolean> => {
				if (initialized) {
					const message: Message<null> = {
						type: SIGN_IN,
						data: null,
					};

					return communicate<null, SignInResponse>(message)
						.then((response) => {
							if (response.type === SIGNED_IN) {
								signedIn = true;
								return Promise.resolve(true);
							} else if (response.type === AUTH_REQUIRED && response.code) {
								if (response.pkce) {
									sessionStorage.setItem(PKCE_CODE_VERIFIER, response.pkce);
								}

								location.href = response.code;
							} else {
								return Promise.reject("Something went wrong during authentication");
							}
						})
						.catch((error) => {
							return Promise.reject(error);
						});
				} else {
					return Promise.reject("Error while signing in. The object has not been initialized yet.");
				}
			},

			/**
			 * Initiates the sign out flow.
			 *
			 * @returns {Promise<boolean>} A promise that resolves when sign out is completed.
			 */
			signOut: (): Promise<boolean> => {
				if (!signedIn) {
					return Promise.reject("You have not signed in yet");
				}
				const message: Message<null> = {
					type: LOGOUT,
				};

				return communicate<null, boolean>(message)
					.then((response) => {
						signedIn = false;
						return Promise.resolve(response);
					})
					.catch((error) => {
						return Promise.reject(error);
					});
			},

			/**
			 * Switches accounts.
			 *
			 * @param {AccountSwitchRequestParams} requestParams Request parameters.
			 *
			 * @returns {Promise<boolean>} A promise that resolves when account switching is successful.
			 *
			 * `requestParams` has the following attributes:
			 *  - username: `string`
			 *	- "userstore-domain": `string`
			 *	- "tenant-domain": `string`
			 *
			 */
			switchAccounts: (requestParams: AccountSwitchRequestParams): Promise<boolean> => {
				if (!initialized) {
					return Promise.reject("The object has not been initialized yet");
				}

				if (!signedIn) {
					return Promise.reject("You have not signed in yet");
				}

				const message: Message<AccountSwitchRequestParams> = {
					type: SWITCH_ACCOUNTS,
					data: requestParams,
				};

				return communicate<AccountSwitchRequestParams, boolean>(message)
					.then((response) => {
						return Promise.resolve(response);
					})
					.catch((error) => {
						return Promise.reject(error);
					});
			},

			/**
			 *
			 * Send the API request to the web worker and returns the response.
			 *
			 * @param {AxiosRequestConfig} config The Axios Request Config object
			 *
			 * @returns {Promise<AxiosResponse>} A promise that resolves with the response data.
			 */
			httpRequest: (config: AxiosRequestConfig): Promise<AxiosResponse> => {
				if (!initialized) {
					return Promise.reject("The object has not been initialized yet ");
				}
				if (!signedIn) {
					return Promise.reject("You have not signed in yet");
				}
				const message: Message<AxiosRequestConfig> = {
					type: API_CALL,
					data: config,
				};
				return communicate<AxiosRequestConfig, AxiosResponse>(message)
					.then((response) => {
						return Promise.resolve(response);
					})
					.catch((error) => {
						return Promise.reject(error);
					});
			},
		};
	}

	return {
		getInstance: (): OAuthInterface => {
			if (instance) {
				return instance;
			} else {
				instance = Constructor();
				return instance;
			}
		},
	};
})();
