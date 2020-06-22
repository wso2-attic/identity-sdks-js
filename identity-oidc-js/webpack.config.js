const path = require('path');

module.exports = {
    context: path.resolve(__dirname, 'client'),
    devtool: 'source-map',
    entry: path.resolve(__dirname, 'dist', 'index.js'),
    mode: 'production',
    module: {
        rules: [{
            test: /\.js?$/,
            use: [{
                loader: "expose-loader",
                options: "IdentityOIDC"
            }],
            exclude: /node_modules/
        }]
    },
    output: {
        filename: 'wso2-identity-oidc.standalone.js',
        path: path.resolve(__dirname, 'dist')
    },
    resolve: {
        extensions: ['.tsx', '.ts', '.jsx', '.js']
    },
};
