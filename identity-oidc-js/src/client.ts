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

import { handleSignIn } from "./actions/sign-in";
import { handleSignOut } from "./actions/sign-out";
import * as AUTHENTICATION_TYPES from "./constants";
import { ConfigInterface } from "./models/client";

/**
 * The login scope.
 * @constant
 * @type {string}
 * @default
 */
const LOGIN_SCOPE = "internal_login";

/**
 * Human task scope.
 * @constant
 * @type {string}
 * @default
 */
const HUMAN_TASK_SCOPE = "internal_humantask_view";

/**
 * Super Tenant Identifier.
 * @constant
 * @type {string}
 * @default
 */
const DEFAULT_SUPER_TENANT = "carbon.super";

/**
 * Default configurations.
 */
const DefaultConfig = {
    autherizationType: AUTHENTICATION_TYPES.AUTHORIZATION_CODE_TYPE,
    clientSecret: null,
    consentDenied: false,
    enablePKCE: true,
    responseMode: null,
    scope: [LOGIN_SCOPE, HUMAN_TASK_SCOPE],
    tenant: DEFAULT_SUPER_TENANT,
    tenantPath: ""
};

/**
 * IdentityAuth class constructor.
 *
 * @export
 * @class IdentityAuth {Singleton}
 * @implements {ConfigInterface} - Configuration interface.
 */
export class IdentityAuth {

    private static _userConfig;
    private static _instance: IdentityAuth = new IdentityAuth(IdentityAuth._userConfig);

    constructor(UserConfig: ConfigInterface) {
        IdentityAuth._userConfig = { ...DefaultConfig, ...UserConfig };

        if (IdentityAuth._instance){
            return IdentityAuth._instance;
        }

        IdentityAuth._instance = this;
    }

    public getUserInfo() {
        // TODO: Implement
        return;
    }

    public validateAuthnentication() {
        // TODO: Implement
        return;
    }

    public getAccessToken() {
        // TODO: Implement
        return;
    }

    /**
     * Sign-in method.
     *
     * @param {() => void} [callback] - Callback method to run on successfull sign-in
     * @returns {Promise<any>} promise.
     * @memberof IdentityAuth
     */
    public signIn(callback?: () => void): Promise<any> {
        return handleSignIn(IdentityAuth._userConfig, callback);
    }

    /**
     * Sign-out method.
     *
     * @param {() => void} [callback] - Callback method to run on successfull sign-in
     * @returns {Promise<any>} promise.
     * @memberof IdentityAuth
     */
    public signOut(callback?: () => void): Promise<any> {
        return handleSignOut(IdentityAuth._userConfig, callback);
    }
}
