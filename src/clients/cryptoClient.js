const openpgp = require('openpgp');
const crypto = require('crypto');

function wrapPublicKey(publicKey) {
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----

${publicKey}
-----END PGP PUBLIC KEY BLOCK-----`;
}

function wrapPrivateKey(privateKey) {
  return `-----BEGIN PGP PRIVATE KEY BLOCK-----

${privateKey}
-----END PGP PRIVATE KEY BLOCK-----`;
}

function wrapEncryptedMessage(encryptedMessage) {
  return `-----BEGIN PGP MESSAGE-----

${encryptedMessage}
-----END PGP MESSAGE-----`;
}

function unwrapEncryptedMessage(encryptedMessage) {
  return encryptedMessage
    .split('BEGIN PGP MESSAGE-----')[1]
    .split('-----END')[0]
    .trim();
}

const cryptoClient = {
  async encryptMessage(publicKey, message) {
    const wrappedPublicKey = wrapPublicKey(publicKey);
    const publicKeyObj = await openpgp.readKey({
      armoredKey: wrappedPublicKey,
    });

    const wrappedMessage = await openpgp.createMessage({ text: message });
    const encryptedMessage = await openpgp.encrypt({
      message: wrappedMessage,
      encryptionKeys: publicKeyObj,
    });

    return unwrapEncryptedMessage(encryptedMessage);
  },

  async decryptMessage(privateKey, encryptedMessage) {
    const wrappedMessage = wrapEncryptedMessage(encryptedMessage);
    const messageObj = await openpgp.readMessage({
      armoredMessage: wrappedMessage,
    });
    const wrappedPrivateKey = wrapPrivateKey(privateKey);
    const privateKeyObj = await openpgp.readPrivateKey({
      armoredKey: wrappedPrivateKey,
    });

    const decryptedMessage = await openpgp.decrypt({
      message: messageObj,
      decryptionKeys: privateKeyObj,
    });

    return decryptedMessage.data;
  },

  sha256(message) {
    const sha256Hasher = crypto.createHash('sha256');
    return sha256Hasher.update(message).digest('hex');
  },
};

module.exports = cryptoClient;
