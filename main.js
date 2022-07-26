"use strict";
exports.__esModule = true;
var WolfSSLDecryptor_1 = require("./WolfSSLDecryptor");
var key = Buffer.from('12345678901234567890123456789012');
var iv = Buffer.from('1234567890123456');
var decrypt = new WolfSSLDecryptor_1.WolfSSLDecryptor('AES-256-CBC', key, iv);
var expected = 'test\0\0\0\0\0\0\0\0\0\0\0\0';
var actual = Buffer.concat([
    decrypt.update(Buffer.from('24d31b1e41fc8c40', 'hex')),
    decrypt.update(Buffer.from('e521531d67c72c20', 'hex')),
    decrypt.finalize()
]).toString();
if (actual == expected) {
    console.log('PASS');
}
else {
    console.log('FAIL', expected, expected.length, actual, actual.length);
}
