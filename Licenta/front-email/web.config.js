// webpack.config.js
const path = require('path');

module.exports = {
  resolve: {
    // Extensions to resolve when importing modules
    extensions: ['.js', '.jsx', '.json'],
    alias: {
      // Resolving 'process' to 'process/browser' for Webpack
      process: require.resolve('process/browser'),
    },
    fallback: {
      // Prevent bundling Node.js modules for the browser
      fs: false, 
      net: false, 
      tls: false, 
    },
  },
  module: {
    rules: [
      {
        test: /\.js$/,  // Transpile .js files
        exclude: /node_modules/,  // Exclude node_modules from transpiling
        use: {
          loader: 'babel-loader',  // Use Babel to transpile
          options: {
            presets: [
              '@babel/preset-env',  // Ensure compatibility with older browsers
              '@babel/preset-react', // For React JSX
            ],
          },
        },
      },
    ],
  },
  mode: 'development',  // You can change to 'production' in production builds
  devtool: 'inline-source-map',  // Helpful for debugging in development
};
