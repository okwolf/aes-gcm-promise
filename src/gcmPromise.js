const { encryptStream, decryptStream } = require('./gcmStream');

module.exports = {
  encrypt: options =>
    new Promise((resolve, reject) => {
      const { plainStream, cipherStream } = options;
      plainStream
        .pipe(encryptStream(options))
        .on('error', reject)
        .pipe(cipherStream)
        .on('finish', () => resolve(cipherStream));
    }),
  decrypt: options =>
    new Promise((resolve, reject) => {
      const { cipherStream, plainStream } = options;
      cipherStream
        .pipe(decryptStream(options))
        .on('error', reject)
        .pipe(plainStream)
        .on('finish', () => resolve(plainStream));
    })
};
