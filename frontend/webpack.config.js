const path = require('path');
//const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;

module.exports = {
    mode: 'production',
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
      //new BundleAnalyzerPlugin(),
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
          //exclude: /node_modules\/(?!bootstrap-vue\/src\/)/,
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
        'vue$': 'vue/dist/vue.esm.js',
        //'bootstrap-vue$': 'bootstrap-vue/src/index.js'
      },
      extensions: ['*', '.js', '.vue', '.json']
    },
  }

