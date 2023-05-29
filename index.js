const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json());

// Load the public key from a file or any other source
function loadPublicKey() {
  // Replace 'public_key.pem' with the path to your public key file
  const publicKey = fs.readFileSync('PublicKey/public_key.pem', 'utf8');
  return publicKey;
}

// Encrypt data using the public key
function encryptData(data, publicKey) {
  const buffer = Buffer.from(data, 'utf8');
  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING
    },
    buffer
  );
  const encodedData = encryptedData.toString('base64');
  return encodedData;
}

function removePadding(buffer) {
  const lastByte = buffer[buffer.length - 1];
  const paddingLength = lastByte;
  return buffer.slice(0, buffer.length - paddingLength);
}

function decryptValue(encryptedValue, appKey) {
  const appKeyBuffer = Buffer.from(appKey, 'base64');
  const encryptedBuffer = Buffer.from(encryptedValue, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-ecb', appKeyBuffer, Buffer.alloc(0));
  decipher.setAutoPadding(false);

  let decryptedBuffer = decipher.update(encryptedBuffer);
  decryptedBuffer = Buffer.concat([decryptedBuffer, decipher.final()]);

  const unpaddedBuffer = removePadding(decryptedBuffer);
  const base64DecodedValue = unpaddedBuffer.toString('utf8');

  return base64DecodedValue;
}

// AES256 encryption with SEK
function encryptAES256(data, sek) {
  sek = Buffer.from(sek, 'base64').slice(0, 32);
  const cipher = crypto.createCipheriv('aes-256-ecb', sek, Buffer.alloc(0));
  cipher.setAutoPadding(true);
  let encryptedData = cipher.update(data, 'utf-8', 'base64');
  encryptedData += cipher.final('base64');
  return encryptedData;
}

// AES256 decryption with SEK
function decryptAES256(encryptedData, sek) {
  const decipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(sek, 'utf8'), Buffer.alloc(0));
  decipher.setAutoPadding(true);
  let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
  decryptedData += decipher.final('utf8');
  return decryptedData;
}

app.post('/encrypt', (req, res) => {
  const data = req.body.data;
  const publicKey = loadPublicKey();
  const encryptedData = encryptData(data, publicKey);
  res.json({ encrypt_data: encryptedData });
});

app.post('/decrypt', (req, res) => {
  const encryptedValue = req.body.encrypted_value;
  const appKey = req.body.app_key;

  const decryptedValue = decryptValue(encryptedValue, appKey);
  res.json({ decrypted_data: decryptedValue });
});

app.post('/encrypt-aes256', (req, res) => {
  const data = req.body.data;
  const sek = req.body.sek;

  const encryptedData = encryptAES256(data, sek);
  res.json({ encrypted_data: encryptedData });
});

app.post('/decrypt-aes256', (req, res) => {
  const encryptedData = req.body.encrypted_data;
  const sek = req.body.sek;

  const decryptedData = decryptAES256(encryptedData, sek);
  res.json({ decrypted_data: decryptedData });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
