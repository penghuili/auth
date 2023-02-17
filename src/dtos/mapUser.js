function mapUser({
  id,
  username,
  publicKey,
  encryptedPrivateKey,
  createdAt,
  updatedAt,
}) {
  return {
    id,
    username,
    publicKey,
    encryptedPrivateKey,
    createdAt,
    updatedAt,
  };
}

module.exports = mapUser;
