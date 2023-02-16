function mapUser({
  id,
  username,
  publicKey,
  encryptedPrivateKey,
  createdAt,
  updatedAt,
  telegramId,
}) {
  return {
    id,
    username,
    publicKey,
    encryptedPrivateKey,
    createdAt,
    updatedAt,
    telegramId,
  };
}

module.exports = mapUser;
