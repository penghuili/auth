import { generateSecret, verifyToken } from 'node-2fa';

import httpErrorCodes from '../shared/js/httpErrorCodes';
import response from '../shared/node/response';
import userClient from '../shared/node/userClient';

const twoFactorClient = {
  async generateSecret(username) {
    const { secret, uri } = generateSecret({
      name: 'peng.kiwi',
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

    const secret = user?.twoFactorSecret?.secret;
    const result = verifyToken(secret, code);
    return result?.delta === 0;
  },

  async enable2FA(userId) {
    const user = await userClient.getByUserId(userId);
    if (!user) {
      return response(httpErrorCodes.NOT_FOUND, 404);
    }

    const updatedUser = await userClient.enable2FA(userId);

    return updatedUser;
  },
};

export default twoFactorClient;
