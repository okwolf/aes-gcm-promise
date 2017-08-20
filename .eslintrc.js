module.exports = {
  extends: ['eslint:recommended'],
  env: {
    node: true,
    es6: true,
    mocha: true
  },
  plugins: ['prettier'],
  rules: {
    'prettier/prettier': [
      'error',
      {
        singleQuote: true
      }
    ]
  }
};
