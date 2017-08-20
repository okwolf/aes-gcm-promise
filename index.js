const gcmPromise = require('./src/gcmPromise');
const gcmStream = require('./src/gcmStream');

module.exports = Object.assign({}, gcmPromise, gcmStream);
