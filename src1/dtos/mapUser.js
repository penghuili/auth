function mapUser({
  id,
  username,
  publicKey,
  encryptedPrivateKey,
  twoFactorSecret,
  twoFactorEnabled,
  createdAt,
  updatedAt,
}) {
  return {
    id,
    username,
    publicKey,
    encryptedPrivateKey,
    twoFactorUri: twoFactorSecret?.uri,
    twoFactorEnabled,
    createdAt,
    updatedAt,
  };
}

export default mapUser;
