var path = require('path')
var webpack = require('webpack')
const TerserPlugin = require('terser-webpack-plugin');

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
        loader: 'babel-loader',
        exclude: /node_modules/
      }

    ]
  },
  resolve: {
    alias: {
      'vue$': 'vue/dist/vue.esm.js'
    },
    extensions: ['*', '.js', '.vue', '.json']
  },
  devServer: {
    historyApiFallback: true,
    noInfo: true,
    overlay: true
  },
  performance: {
    hints: false
  },
}

if (process.env.NODE_ENV === 'production') {
  module.exports.devtool = 'false'
  // http://vue-loader.vuejs.org/en/workflow/production.html
  module.exports.plugins = (module.exports.plugins || []).concat([
    new webpack.DefinePlugin({
      'process.env': {
        NODE_ENV: '"production"'
      }
    }),
    new TerserPlugin({
      sourceMap: false
    }),
    new webpack.LoaderOptionsPlugin({
      minimize: true
    })
  ])
}
