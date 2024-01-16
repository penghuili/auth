import { generateSecret, verifyToken } from 'node-2fa';
import { decryptMessageAsymmetric } from '../shared/js/encryption';
import { httpErrorCodes } from '../shared/js/httpErrorCodes';
import { response } from '../shared/node/response';
import { userClient } from '../shared/node/userClient';

export const twoFactorClient = {
  async generateSecret(username) {
    const { secret, uri } = generateSecret({
      name: 'peng37.com',
      account: username,
    });

    await userClient.save2FASecret(username, { secret, uri });

    return uri;
  },

  async verifyCode(userId, code) {
    const user = await userClient.getByUserId(userId);
    if (!user) {
      return response(httpErrorCodes.NOT_FOUND, 404);
    }

    const secret = user?.twoFactorSecret?.secretForBackend;
    if (!secret) {
      return response(httpErrorCodes.BAD_REQUEST, 400);
    }

    const decryptedSecret = await decryptMessageAsymmetric(
      JSON.parse(`"${process.env.BACKEND_PRIVATE_KEY}"`),
      secret
    );
    const result = verifyToken(decryptedSecret, code);
    const delta = result?.delta;
    return delta === 0 || delta === 1 || delta === -1;
  },

  async enable2FA(userId) {
    const user = await userClient.getByUserId(userId);
    if (!user) {
      return response(httpErrorCodes.NOT_FOUND, 404);
    }

    const updatedUser = await userClient.enable2FA(userId);

    return updatedUser;
  },

  async disable2FA(userId) {
    const user = await userClient.getByUserId(userId);
    if (!user) {
      return response(httpErrorCodes.NOT_FOUND, 404);
    }

    const updatedUser = await userClient.disable2FA(userId);

    return updatedUser;
  },
};
