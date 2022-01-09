// Generated using webpack-cli https://github.com/webpack/webpack-cli

const path = require('path');

const isProduction = process.env.NODE_ENV == 'production';


const config = {
    entry: {
      bundle: [
        './src/main.js',
        ],
      style: [
        './src/style.js',
      ]
    },
    output: {
        path: path.resolve(__dirname, './static/dist'),
        publicPath: '/dist/',
        filename: '[name].min.js'
    },
    plugins: [
    ],
    module: {
        rules: [
            {
              test: /\.css$/,
              use: [
                'vue-style-loader',
                'css-loader'
              ],
            },
            {
              test: /\.js$/,
              exclude: /node_modules/,
              loader: 'babel-loader',
              options: {
                presets: ['@babel/preset-env']
              }
            },
        ],
    },
    resolve: {
      alias: {
        'vue$': 'vue/dist/vue.esm.js'
      },
      extensions: ['*', '.js', '.vue', '.json']
    },
};

module.exports = () => {
    config.mode = 'production';

    return config;
};
