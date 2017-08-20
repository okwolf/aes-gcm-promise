const { expect } = require('chai');
const { encrypt, decrypt } = require('../');
const { readStreamWith, writeStreamToBuffer } = require('./streamUtils');
const aesGcmTestVectors = require('./gcmTestVectors');

describe('AES GCM Promises', () => {
  describe('for encryption', () => {
    it('should fail with no key', () => {
      const encryptOptions = {
        plainStream: readStreamWith(''),
        cipherStream: writeStreamToBuffer(),
        iv: Buffer.alloc(12)
      };
      return encrypt(encryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'key is required');
      });
    });
    it('should fail with no IV', () => {
      const encryptOptions = {
        plainStream: readStreamWith(''),
        cipherStream: writeStreamToBuffer(),
        key: Buffer.alloc(16)
      };
      return encrypt(encryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'iv is required');
      });
    });
    it('should fail with bad key size', () => {
      const encryptOptions = {
        plainStream: readStreamWith(''),
        cipherStream: writeStreamToBuffer(),
        key: Buffer.alloc(0),
        iv: Buffer.alloc(12)
      };
      return encrypt(encryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'bad key size');
      });
    });
    it('should fail with bad IV size', () => {
      const encryptOptions = {
        plainStream: readStreamWith(''),
        cipherStream: writeStreamToBuffer(),
        key: Buffer.alloc(16),
        iv: Buffer.alloc(0)
      };
      return encrypt(encryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'Invalid IV length');
      });
    });
    it('should encrypt with no AAD', () => {
      const encryptOptions = {
        plainStream: readStreamWith(Buffer.alloc(16)),
        cipherStream: writeStreamToBuffer(),
        key: Buffer.alloc(16),
        iv: Buffer.alloc(12)
      };
      const expectedEncrypted = Buffer.from(
        '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
        'hex'
      );
      return encrypt(encryptOptions).then(cipherStream => {
        expect(cipherStream.getBuffer()).to.deep.equal(expectedEncrypted);
      });
    });
    it('should encrypt with AAD', () => {
      const encryptOptions = {
        plainStream: readStreamWith(Buffer.alloc(16)),
        cipherStream: writeStreamToBuffer(),
        key: Buffer.alloc(16),
        iv: Buffer.alloc(12),
        aad: Buffer.alloc(16)
      };
      const expectedEncrypted = Buffer.from(
        '0388dace60b6a392f328c2b971b2fe78d24e503a1bb037071c71b35d987b8657',
        'hex'
      );
      return encrypt(encryptOptions).then(cipherStream => {
        expect(cipherStream.getBuffer()).to.deep.equal(expectedEncrypted);
      });
    });
  });
  describe('for decryption', () => {
    it('should fail with no key', () => {
      const decryptOptions = {
        cipherStream: readStreamWith(''),
        plainStream: writeStreamToBuffer(),
        iv: Buffer.alloc(12)
      };
      return decrypt(decryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'key is required');
      });
    });
    it('should fail with no IV', () => {
      const decryptOptions = {
        cipherStream: readStreamWith(''),
        plainStream: writeStreamToBuffer(),
        key: Buffer.alloc(16)
      };
      return decrypt(decryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'iv is required');
      });
    });
    it('should fail with bad key size', () => {
      const decryptOptions = {
        cipherStream: readStreamWith(''),
        plainStream: writeStreamToBuffer(),
        key: Buffer.alloc(0),
        iv: Buffer.alloc(12)
      };
      return decrypt(decryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'bad key size');
      });
    });
    it('should fail with bad IV size', () => {
      const decryptOptions = {
        cipherStream: readStreamWith(''),
        plainStream: writeStreamToBuffer(),
        key: Buffer.alloc(16),
        iv: Buffer.alloc(0)
      };
      return decrypt(decryptOptions).catch(error => {
        expect(error).to.exist.and.be
          .instanceof(Error)
          .and.have.property('message', 'Invalid IV length');
      });
    });
    it('should decrypt with no AAD', () => {
      const ciphertext = Buffer.from(
        '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
        'hex'
      );
      const decryptOptions = {
        cipherStream: readStreamWith(ciphertext),
        plainStream: writeStreamToBuffer(),
        key: Buffer.alloc(16),
        iv: Buffer.alloc(12)
      };
      return decrypt(decryptOptions).then(plainStream => {
        expect(plainStream.getBuffer()).to.deep.equal(Buffer.alloc(16));
      });
    });
    it('should decrypt with AAD', () => {
      const ciphertext = Buffer.from(
        '0388dace60b6a392f328c2b971b2fe78d24e503a1bb037071c71b35d987b8657',
        'hex'
      );
      const decryptOptions = {
        cipherStream: readStreamWith(ciphertext),
        plainStream: writeStreamToBuffer(),
        key: Buffer.alloc(16),
        iv: Buffer.alloc(12),
        aad: Buffer.alloc(16)
      };
      return decrypt(decryptOptions).then(plainStream => {
        expect(plainStream.getBuffer()).to.deep.equal(Buffer.alloc(16));
      });
    });
  });
  describe('NIST test vector', () => {
    aesGcmTestVectors.forEach(
      ({ testVector, plaintext, encrypted, streamOptions }) => {
        describe(JSON.stringify(testVector), () => {
          it('should encrypt', () => {
            const encryptOptions = Object.assign({}, streamOptions, {
              plainStream: readStreamWith(plaintext),
              cipherStream: writeStreamToBuffer()
            });
            return encrypt(encryptOptions).then(cipherStream => {
              expect(cipherStream.getBuffer()).to.deep.equal(encrypted);
            });
          });
          it('should decrypt', () => {
            const decryptOptions = Object.assign({}, streamOptions, {
              cipherStream: readStreamWith(encrypted),
              plainStream: writeStreamToBuffer()
            });
            return decrypt(decryptOptions).then(plainStream => {
              expect(plainStream.getBuffer()).to.deep.equal(plaintext);
            });
          });
          it('should fail to authenticate bad data', () => {
            const badTagEncrypted = Buffer.from(encrypted);
            badTagEncrypted.swap16();
            const decryptOptions = Object.assign({}, streamOptions, {
              cipherStream: readStreamWith(badTagEncrypted),
              plainStream: writeStreamToBuffer()
            });
            return decrypt(decryptOptions).catch(error => {
              expect(error).to.exist.and.be
                .instanceof(Error)
                .and.have.property(
                  'message',
                  'Unsupported state or unable to authenticate data'
                );
            });
          });
        });
      }
    );
  });
  it('should properly chunk non-trival amounts of plaintext', () => {
    // Use 1MB of plaintext to exercise the chunking
    const plaintext = Buffer.alloc(1024 * 1024);
    const expectedTag = Buffer.from('28f0cbf41ca3ee08d208213c816357f4', 'hex');
    const streamOptions = {
      key: Buffer.alloc(16),
      iv: Buffer.alloc(12),
      aad: Buffer.alloc(16)
    };
    const encryptOptions = Object.assign({}, streamOptions, {
      plainStream: readStreamWith(plaintext),
      cipherStream: writeStreamToBuffer()
    });
    return encrypt(encryptOptions)
      .then(cipherStream => {
        const encrypted = cipherStream.getBuffer();
        const tag = encrypted.slice(-16, encrypted.length);
        expect(tag).to.deep.equal(expectedTag);
        return encrypted;
      })
      .then(encrypted => {
        const encryptedStream = readStreamWith(encrypted);
        const decryptedStream = writeStreamToBuffer();
        const decryptOptions = Object.assign({}, streamOptions, {
          cipherStream: encryptedStream,
          plainStream: decryptedStream
        });
        return decrypt(decryptOptions);
      })
      .then(decryptedStream => {
        expect(decryptedStream.getBuffer()).to.deep.equal(plaintext);
      });
  });
});
