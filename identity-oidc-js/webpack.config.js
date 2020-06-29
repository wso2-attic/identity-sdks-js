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
 *
 */

const path = require("path");

module.exports = {
    context: path.resolve(__dirname, "client"),
    devtool: "source-map",
    entry: path.resolve(__dirname, "dist", "index.js"),
    mode: "production",
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: [{
                    loader: "awesome-typescript-loader?tsconfig=tsconfig.umd.json",
                    query: {
                        declaration: false,
                    }
                }],  
                exclude: /node_modules/
            }
        ]
    },
    output: {
        filename: "wso2-identity-oidc.standalone.js",
        path: path.resolve(__dirname, "bundle"),
        libraryTarget: "umd",
        library: "IdentityOIDC",
        umdNamedDefine: true
    },
    resolve: {
        extensions: [".tsx", ".ts", ".jsx", ".js"]
    },
};
