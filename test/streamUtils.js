const stream = require('stream');

// 16KB
const CHUNK_SIZE = 16 * 1024;

module.exports = {
  readStreamWith: data => {
    const readStream = new stream.PassThrough();
    process.nextTick(() => {
      for (let i = 0; i < data.length; i += CHUNK_SIZE) {
        const remainingBytes = data.length - i;
        const nextChunkSize =
          remainingBytes < CHUNK_SIZE ? remainingBytes : CHUNK_SIZE;
        const nextChunk = data.slice(i, i + nextChunkSize);
        readStream.write(nextChunk);
      }
      readStream.end();
    });
    return readStream;
  },
  writeStreamToBuffer() {
    let writeBuffer = Buffer.alloc(0);
    const writeStream = new stream.Writable({
      write(chunk, encoding, callback) {
        writeBuffer = Buffer.concat([writeBuffer, chunk]);
        callback();
      }
    });
    writeStream.getBuffer = () => writeBuffer;
    return writeStream;
  }
};
