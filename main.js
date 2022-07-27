"use strict";
exports.__esModule = true;
var WolfSSLEVP_1 = require("./WolfSSLEVP");
var WolfSSLHmac_1 = require("./WolfSSLHmac");
var key = Buffer.from('12345678901234567890123456789012');
var iv = Buffer.from('1234567890123456');
var decrypt = new WolfSSLEVP_1.WolfSSLDecryptor('AES-256-CBC', key, iv);
var encrypt = new WolfSSLEVP_1.WolfSSLEncryptor('AES-256-CBC', key, iv);
var expected = 'test';
var expectedCiphertext = '24d31b1e41fc8c40e521531d67c72c20';
// 17 bytes to test padding
var expectedLonger = '12345678901234567';
var expectedLongerDigest = 'db6ff3fef0c61ef0d43d7020f6de2bb570a2dbf78921bb185242971b9c8e8d85afb6cbfc31a2a1de3b538da6b784e7424e84e3d8973bcf57798b3e3b67d6b45e';
var ciphertext = Buffer.concat([
    encrypt.update(Buffer.from(expected)),
    encrypt.finalize()
]);
if (ciphertext.toString('hex') == expectedCiphertext) {
    console.log('PASS ciphertext match');
}
else {
    console.log('Fail ciphertext does not match what we expected');
}
var actual = Buffer.concat([
    decrypt.update(ciphertext),
    decrypt.finalize()
]).toString();
if (actual == expected) {
    console.log('PASS plaintext match');
}
else {
    console.log('FAIL plaintext does not match what we expected', expected, expected.length, actual, actual.length);
}
// finalize frees the evp context, need to make it again
decrypt = new WolfSSLEVP_1.WolfSSLDecryptor('AES-256-CBC', key, iv);
encrypt = new WolfSSLEVP_1.WolfSSLEncryptor('AES-256-CBC', key, iv);
var parts = [];
var i;
// lets put the api through its paces
for (i = 0; i < expectedLonger.length; i++) {
    parts.push(encrypt.update(Buffer.from(expectedLonger[i])));
}
parts.push(encrypt.finalize());
var ciphertextLonger = Buffer.concat(parts);
parts = [];
for (i = 0; i < ciphertextLonger.length; i++) {
    parts.push(decrypt.update(ciphertextLonger.subarray(i, i + 1)));
}
parts.push(decrypt.finalize());
var actualLonger = Buffer.concat(parts).toString();
if (actualLonger == expectedLonger) {
    console.log('PASS longer plaintext match');
}
else {
    console.log('FAIL longer plaintext does not match what we expected', expectedLonger, expectedLonger.length, actualLonger, actualLonger.length);
}
parts = [];
var encryptStream = new WolfSSLEVP_1.WolfSSLEncryptionStream('AES-256-CBC', key, iv);
encryptStream.on('data', function (chunk) {
    parts.push(chunk);
});
encryptStream.on('end', function () {
    var streamedCiphertext = Buffer.concat(parts);
    if (streamedCiphertext.toString('hex') == expectedCiphertext) {
        console.log('PASS streamed ciphertext match');
    }
    else {
        console.log('Fail streamed ciphertext does not match what we expected');
    }
    parts = [];
    var decryptStream = new WolfSSLEVP_1.WolfSSLDecryptionStream('AES-256-CBC', key, iv);
    decryptStream.on('data', function (chunk) {
        parts.push(chunk);
    });
    decryptStream.on('end', function () {
        var streamedPlaintext = Buffer.concat(parts);
        if (streamedPlaintext.toString() == expected) {
            console.log('PASS streamed plaintext match');
        }
        else {
            console.log('Fail streamed plaintext does not match what we expected');
        }
    });
    for (i = 0; i < streamedCiphertext.length; i++) {
        decryptStream.write(streamedCiphertext.subarray(i, i + 1));
    }
    decryptStream.end();
});
for (i = 0; i < expected.length; i++) {
    encryptStream.write(expected[i]);
}
encryptStream.end();
var hmac = new WolfSSLHmac_1.WolfSSLHmac('SHA3_512', key);
hmac.update(Buffer.from(expectedLonger));
var actualDigest = hmac.finalize();
if (actualDigest.toString('hex') == expectedLongerDigest) {
    console.log('PASS digest match');
}
else {
    console.log('Fail digest mismatch');
}
var hmacParts = [];
var hmacStream = new WolfSSLHmac_1.WolfSSLHmacStream('SHA3_512', key);
hmacStream.on('data', function (chunk) {
    hmacParts.push(chunk);
});
hmacStream.on('end', function () {
    var streamedDigest = Buffer.concat(hmacParts);
    if (streamedDigest.toString('hex') == expectedLongerDigest) {
        console.log('PASS streamed digest match');
    }
    else {
        console.log('Fail streamed digest does not match what we expected');
    }
});
for (i = 0; i < expectedLonger.length; i++) {
    hmacStream.write(expectedLonger[i]);
}
hmacStream.end();
