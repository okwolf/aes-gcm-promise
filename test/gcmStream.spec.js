const { expect } = require('chai');
const { encryptStream, decryptStream } = require('../');
const { readStreamWith, writeStreamToBuffer } = require('./streamUtils');
const aesGcmTestVectors = require('./gcmTestVectors');

describe('AES GCM Streams', () => {
  describe('for encryption', () => {
    it('should fail with no key', () => {
      expect(() =>
        encryptStream({
          iv: Buffer.alloc(12)
        })
      ).to.throw('key is required');
    });
    it('should fail with no IV', () => {
      expect(() =>
        encryptStream({
          key: Buffer.alloc(16)
        })
      ).to.throw('iv is required');
    });
    it('should fail with bad key size', () => {
      expect(() =>
        encryptStream({
          key: Buffer.alloc(0),
          iv: Buffer.alloc(12)
        })
      ).to.throw('bad key size');
    });
    it('should fail with bad IV size', () => {
      expect(() =>
        encryptStream({
          key: Buffer.alloc(16),
          iv: Buffer.alloc(0)
        })
      ).to.throw('Invalid IV length');
    });
    it('should encrypt with no AAD', done => {
      const readStream = readStreamWith(Buffer.alloc(16));
      const writeStream = writeStreamToBuffer();
      const expectedEncrypted = Buffer.from(
        '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
        'hex'
      );
      readStream
        .pipe(
          encryptStream({
            key: Buffer.alloc(16),
            iv: Buffer.alloc(12)
          })
        )
        .pipe(writeStream)
        .on('finish', () => {
          expect(writeStream.getBuffer()).to.deep.equal(expectedEncrypted);
          done();
        });
    });
    it('should encrypt with AAD', done => {
      const readStream = readStreamWith(Buffer.alloc(16));
      const writeStream = writeStreamToBuffer();
      const expectedEncrypted = Buffer.from(
        '0388dace60b6a392f328c2b971b2fe78d24e503a1bb037071c71b35d987b8657',
        'hex'
      );
      readStream
        .pipe(
          encryptStream({
            key: Buffer.alloc(16),
            iv: Buffer.alloc(12),
            aad: Buffer.alloc(16)
          })
        )
        .pipe(writeStream)
        .on('finish', () => {
          expect(writeStream.getBuffer()).to.deep.equal(expectedEncrypted);
          done();
        });
    });
  });
  describe('for decryption', () => {
    it('should fail with no key', () => {
      expect(() =>
        decryptStream({
          iv: Buffer.alloc(12)
        })
      ).to.throw('key is required');
    });
    it('should fail with no IV', () => {
      expect(() =>
        decryptStream({
          key: Buffer.alloc(16)
        })
      ).to.throw('iv is required');
    });
    it('should fail with bad key size', () => {
      expect(() =>
        decryptStream({
          key: Buffer.alloc(0),
          iv: Buffer.alloc(12)
        })
      ).to.throw('bad key size');
    });
    it('should fail with bad IV size', () => {
      expect(() =>
        decryptStream({
          key: Buffer.alloc(16),
          iv: Buffer.alloc(0)
        })
      ).to.throw('Invalid IV length');
    });
    it('should decrypt with no AAD', done => {
      const readStream = readStreamWith(
        Buffer.from(
          '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
          'hex'
        )
      );
      const writeStream = writeStreamToBuffer();
      readStream
        .pipe(
          decryptStream({
            key: Buffer.alloc(16),
            iv: Buffer.alloc(12)
          })
        )
        .pipe(writeStream)
        .on('finish', () => {
          expect(writeStream.getBuffer()).to.deep.equal(Buffer.alloc(16));
          done();
        });
    });
    it('should decrypt with AAD', done => {
      const readStream = readStreamWith(
        Buffer.from(
          '0388dace60b6a392f328c2b971b2fe78d24e503a1bb037071c71b35d987b8657',
          'hex'
        )
      );
      const writeStream = writeStreamToBuffer();
      readStream
        .pipe(
          decryptStream({
            key: Buffer.alloc(16),
            iv: Buffer.alloc(12),
            aad: Buffer.alloc(16)
          })
        )
        .pipe(writeStream)
        .on('finish', () => {
          expect(writeStream.getBuffer()).to.deep.equal(Buffer.alloc(16));
          done();
        });
    });
  });
  describe('NIST test vector', () => {
    aesGcmTestVectors.forEach(
      ({ testVector, plaintext, encrypted, streamOptions }) => {
        describe(JSON.stringify(testVector), () => {
          it('should encrypt', done => {
            const readStream = readStreamWith(plaintext);
            const writeStream = writeStreamToBuffer();
            readStream
              .pipe(encryptStream(streamOptions))
              .pipe(writeStream)
              .on('finish', () => {
                expect(writeStream.getBuffer()).to.deep.equal(encrypted);
                done();
              });
          });
          it('should decrypt', done => {
            const readStream = readStreamWith(encrypted);
            const writeStream = writeStreamToBuffer();
            readStream
              .pipe(decryptStream(streamOptions))
              .pipe(writeStream)
              .on('finish', () => {
                expect(writeStream.getBuffer()).to.deep.equal(plaintext);
                done();
              });
          });
          it('should fail to authenticate bad data', done => {
            const badTagEncrypted = Buffer.from(encrypted);
            badTagEncrypted.swap16();
            const badTagStream = readStreamWith(badTagEncrypted);
            badTagStream
              .pipe(decryptStream(streamOptions))
              .on('error', error => {
                expect(error).to.exist.and.be
                  .instanceof(Error)
                  .and.have.property(
                    'message',
                    'Unsupported state or unable to authenticate data'
                  );
                done();
              });
          });
        });
      }
    );
  });
});
