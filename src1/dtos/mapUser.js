export function mapUser({
  id,
  username,
  publicKey,
  encryptedPrivateKey,
  twoFactorSecret,
  twoFactorEnabled,
  twoFactorChecked,
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
    twoFactorChecked,
    createdAt,
    updatedAt,
  };
}
