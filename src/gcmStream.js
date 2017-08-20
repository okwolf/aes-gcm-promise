const crypto = require('crypto');
const stream = require('stream');

const TAG_LENGTH = 16;
const AES_GCM_ALGORITHMS = {
  16: 'aes-128-gcm',
  24: 'aes-192-gcm',
  32: 'aes-256-gcm'
};

const supportedAlgorithms = crypto.getCiphers();
const unsupportedAlgorithms = Object.keys(AES_GCM_ALGORITHMS)
  .map(key => AES_GCM_ALGORITHMS[key])
  .filter(algorithm => !supportedAlgorithms.includes(algorithm));
// We won't be testing in any environments old enough to be missing GCM support,
// but we're still keeping this to explain the problem to anyone unlucky enough
// to be running that old of a version.
/* istanbul ignore next */
if (unsupportedAlgorithms.length) {
  throw new Error(
    `Please upgrade your version of Node.js. The following algorithms are not supported: ${unsupportedAlgorithms.join(
      ', '
    )}`
  );
}

module.exports = {
  encryptStream({ key, iv, aad }) {
    if (!key) {
      throw new Error('key is required');
    }
    if (!iv) {
      throw new Error('iv is required');
    }
    // Look up algorithm name based on key length
    const algorithmName = AES_GCM_ALGORITHMS[key.length];
    if (!algorithmName) {
      throw new Error('bad key size');
    }
    // Initialize encryption with the algorithm, key, IV, and AAD
    const cipher = crypto.createCipheriv(algorithmName, key, iv);
    if (aad) {
      cipher.setAAD(aad);
    }
    // Return a Transform stream to process the data in chunks
    return new stream.Transform({
      // For each chunk of plaintext
      transform(plaintextChunk, encoding, callback) {
        // Compute the ciphertext for the plaintext chunk
        const ciphertextChunk = cipher.update(plaintextChunk);
        // Send the ciphertext to the output half of our stream
        // The first argument to the callback is null when there is no error
        callback(null, ciphertextChunk);
      },
      // And after the entire stream of plaintext is flushed
      flush(callback) {
        // Compute the authentication tag over all the input
        const tag = Buffer.concat([cipher.final(), cipher.getAuthTag()]);
        // And add the tag at the end of the output stream
        this.push(tag);
        // Always call the callback when we're done transforming this chunk
        callback();
      }
    });
  },
  decryptStream({ key, iv, aad }) {
    if (!key) {
      throw new Error('key is required');
    }
    if (!iv) {
      throw new Error('iv is required');
    }
    // Look up algorithm name based on key length
    const algorithmName = AES_GCM_ALGORITHMS[key.length];
    if (!algorithmName) {
      throw new Error('bad key size');
    }
    // Initialize decryption with the algorithm, key, IV, and AAD
    const decipher = crypto.createDecipheriv(algorithmName, key, iv);
    if (aad) {
      decipher.setAAD(aad);
    }
    // Keep track of the last chunk of data
    // so that we can split the final chunk into remaining ciphertext and tag
    let previousChunk;
    // Return a Transform stream to process the data in chunks
    return new stream.Transform({
      // Then for each chunk of ciphertext
      transform(ciphertextChunk, encoding, callback) {
        // If we've processed at least one chunk before
        if (previousChunk) {
          // Compute the plaintext of the previous chunk
          const plaintextChunk = decipher.update(previousChunk);
          // And send the plaintext to the output half of our stream
          this.push(plaintextChunk);
        }
        // Save the current chunk to be processed when either:
        // * The next chunk is processed and we know this isn't the last chunk
        // * Flush is called and this is in fact the last chunk
        previousChunk = ciphertextChunk;
        // Always call the callback when we're done transforming this chunk
        callback();
      },
      // After the entire stream of ciphertext is flushed
      flush(callback) {
        // Split the last chunk up into the remaining ciphertext and tag
        const remainingCiphertext = previousChunk.slice(0, -TAG_LENGTH);
        const tag = previousChunk.slice(-TAG_LENGTH, previousChunk.length);
        // Tell our decryption what authentication tag value to compare against
        decipher.setAuthTag(tag);
        try {
          // Compute the plaintext of the remaining ciphertext
          const remainingPlaintext = Buffer.concat([
            decipher.update(remainingCiphertext),
            decipher.final()
          ]);
          // And add the plaintext at the end of the output stream
          this.push(remainingPlaintext);
          // Always call the callback when we're done transforming this chunk
          callback();
          // If there's an error
        } catch (error) {
          // Send the error to our callback
          // This can be listened for by adding .on('error', error => {})
          callback(error);
        }
      }
    });
  }
};
