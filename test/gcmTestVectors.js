const aesGcmTestVectors = require('./aes-gcm-test-vectors');

// From http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
module.exports = aesGcmTestVectors.map(testVector => {
  const convertedTestVector = Object.assign({}, testVector);
  Object.keys(convertedTestVector).forEach(key => {
    const value = convertedTestVector[key];
    if (typeof value === 'string') {
      convertedTestVector[key] = Buffer.from(convertedTestVector[key], 'hex');
    }
  });
  const {
    k: key,
    p: plaintext,
    a: aad,
    iv,
    c: ciphertext,
    t: tag
  } = convertedTestVector;
  const encrypted = Buffer.concat([ciphertext, tag]);
  const streamOptions = {
    key,
    iv,
    aad
  };
  return {
    testVector,
    plaintext,
    encrypted,
    streamOptions
  };
});
