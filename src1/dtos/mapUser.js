export function mapUser({
  id,
  username,
  email,
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
    email,
    publicKey,
    encryptedPrivateKey,
    twoFactorUri: twoFactorSecret?.uri,
    twoFactorEnabled,
    twoFactorChecked,
    createdAt,
    updatedAt,
  };
}
