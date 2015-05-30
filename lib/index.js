var crypto = require('crypto');
var ecc = require('eccrypto');
var Buffer = require('buffer').Buffer;

module.exports = {
    templateHeader: '-----BEGIN LICENSE KEY-----\n',
    templateFooter: '\n-----END LICENSE KEY-----',

    /**
     * @param data {object} The data to be signed and used in the license.
     * @param privateKey {Buffer} The private key to use for signing.
     * @return {Promise} A promise to return the license string.
     */
    generate: function (data, privateKey) {
        if (!data) {
            throw new Error('Data is required to generate a license.');
        }

        if (!privateKey) {
            throw new Error('Private key is required to generate a license.');
        }

        if (!Buffer.isBuffer(privateKey)) {
            throw new Error('Private key must be a Buffer to generate a license.');
        }

        var self = this,
            msg = crypto.createHash('sha256').update(JSON.stringify(data)).digest();

        return ecc.sign(privateKey, msg).then(function (sig) {
            return new Promise(function (resolve, reject) {
                resolve(self.templateHeader + obj2kv(data) + '\n' + formatSignature(sig) + self.templateFooter);
            });
        });
    },

    /**
     * Verifies a license by validating the information provided against the signature, and
     * parsing back out the data object that was used to generate the license.
     *
     * @param data {object} The data to be signed and used in the license.
     * @param publicKey {Buffer} The private key to use for signing.
     * @return {Promise} A promise to verify the license stringand return the data object.
     */
    verify: function (license, publicKey) {
        if (!license) {
            throw new Error('License string is required to verify a license.');
        }

        if (!publicKey) {
            throw new Error('Public key is required to verify a license.');
        }

        if (!Buffer.isBuffer(publicKey)) {
            throw new Error('Public key must be a Buffer to verify a license.');
        }

        var data = license.replace(this.templateHeader, '').replace(this.templateFooter, '').split('\n\n'),
            dataObject = kv2obj(data[0]),
            msg = crypto.createHash('sha256').update(JSON.stringify(dataObject)).digest(),
            sig = parseSignature(data[1]);

        return ecc.verify(publicKey, msg, sig).then(function () {
            return new Promise(function (resolve, reject) {
                resolve(dataObject);
            });
        });
    }
};

/**
 * Converts an object to string KV output.
 *
 * @private
 * @param data {object} The data to convert.
 * @return {string}
 */
function obj2kv(data) {
    var str = '';

    for (var key in data) {
        str += key + ': ' + data[key] + '\n';
    }

    return str;
}

/**
 * Converts a string in KV format to an object.
 *
 * @private
 * @param data {string} The data to convert.
 * @return {object}
 */
function kv2obj(data) {
    var lines = data.split('\n'),
        obj = {};

    for (var i = 0; i < lines.length; ++i) {
        var line = lines[i].split(': ');
        obj[line[0]] = line[1];
    }

    return obj;
}

/**
 * Formats the signature for output.
 *
 * @private
 * @param signature {Buffer} The signature buffer.
 * @return {string} The signature string.
 */
function formatSignature(sig) {
    var str = sig.toString('hex').toUpperCase(),
        idx = 0,
        step = 32,
        sub = null;

    // insert a newline every `step` characters
    while(sub = str.substr(idx, step)) {
        str = str.substr(0, idx) + sub + '\n' + str.substr(idx + step);
        idx += step + 1;
    }

    return str.trim();
}

/**
 * Parses the signature for verification.
 *
 * @private
 * @param signature {string} The signature string.
 * @return {Buffer} The signature buffer.
 */
function parseSignature(sig) {
    return new Buffer(sig.replace(/\n/g, ''), 'hex');
}