var crypto = require('crypto')
var encoding = require("encoding");
	
var algorithm = 'aes-256-cbc'
var hmacBytesLen = 32;
var ivByteLen=16;

function encrypt(text, keybuf) {
	
	var ivbuf = encoding.convert("staticivstaticiv");
    var cipher = crypto.createCipheriv(algorithm,keybuf, ivbuf);
    var encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    var resBuffer =  Buffer.concat([ivbuf, encrypted]);
    var hmac = crypto.createHmac("sha256", keybuf).update(resBuffer).digest();
    var res =   Buffer.concat([resBuffer, hmac]).toString('base64')//resBuffer.toString('base64') + hmac;

    return res;
}

function decrypt(cipher_text, keybuf){
    cipherBuffer = new Buffer(cipher_text, 'base64');
    var sentLen = cipherBuffer.length;
    var ivbuf = cipherBuffer.slice(0, ivByteLen);
    var ct = cipherBuffer.slice(ivByteLen, sentLen - hmacBytesLen);
    var hmac = cipherBuffer.slice( sentLen - hmacBytesLen, sentLen);
    var resBuffer =  Buffer.concat([ivbuf, ct]);
    var chmac = crypto.createHmac("sha256", keybuf).update(resBuffer).digest().toString('base64')

    if ( chmac != hmac.toString('base64') ) {
        console.log("Encrypted Blob has been tampered with...");
        return null;
    }

    var decryptor = crypto.createDecipheriv(algorithm, keybuf, ivbuf);
    var decryptedText = decryptor.update(ct, 'base64', 'utf-8');
    decryptedText += decryptor.final('utf-8');
    return decryptedText;
}

var key = "DH6asttV1CL2yp6YaXPimFSHc9BM3xiw";
var data = "secret message";
var keybuf = new Buffer(key);
var databuf = new Buffer(data);

var ciphertext = encrypt(data, keybuf);
var decrypted = decrypt(ciphertext, keybuf);



