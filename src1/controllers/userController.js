import { twoFactorClient } from '../clients/twoFactorClient';
import { mapUser } from '../dtos/mapUser';
import { telegramClient } from '../shared-private/node/telegramClient';
import { encryptMessageAsymmetric } from '../shared/js/encryption';
import { httpErrorCodes } from '../shared/js/httpErrorCodes';
import { isValidUsername } from '../shared/js/regex';
import { hasValidIssuedAt } from '../shared/node/hasValidIssuedAt';
import { parseRequest } from '../shared/node/parseRequest';
import { response } from '../shared/node/response';
import { tokenClient } from '../shared/node/tokenClient';
import { userClient } from '../shared/node/userClient';
import { verifyAccessTokenMiddleware } from '../shared/node/verifyAccessTokenMiddleware';

async function getUser(username, email) {
  if (username) {
    return userClient.getByUsername(username);
  }

  if (email) {
    return userClient.getByEmail(email);
  }

  return null;
}

export const userController = {
  async signup(request) {
    const {
      body: { username, email, publicKey, encryptedPrivateKey },
    } = parseRequest(request);

    try {
      if (!username && !email) {
        return response(httpErrorCodes.NO_USERNAME_OR_EMAIL, 400);
      }

      if (username) {
        const isValidName = isValidUsername(username);
        if (!isValidName) {
          return response(httpErrorCodes.INVALID_USERNAME, 400);
        }
      }

      const existingUser = await getUser(username, email);
      if (existingUser) {
        return response(httpErrorCodes.ALREADY_EXISTS, 400);
      }

      const { id } = await userClient.create({
        username,
        email,
        publicKey,
        encryptedPrivateKey,
      });

      await telegramClient.sendMessage(process.env.ADMIN_TELEGRAM_ID, `Someone signed up :)`);

      return response({ id, username, email }, 200);
    } catch (e) {
      console.log('signup error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async getUserPublic(request) {
    const {
      pathParams: { username, email },
    } = parseRequest(request);

    try {
      const user = await getUser(username, email);

      if (user) {
        const { id, publicKey, encryptedPrivateKey, signinChallenge } = user;
        const encryptedChallenge = await encryptMessageAsymmetric(publicKey, signinChallenge);

        return response({ id, publicKey, encryptedPrivateKey, encryptedChallenge }, 200);
      }

      return response(httpErrorCodes.NOT_FOUND, 404);
    } catch (e) {
      console.log('get pubic user error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async getUserPublic2(request) {
    const {
      body: { username, email },
    } = parseRequest(request);

    try {
      const user = await getUser(username, email);

      if (user) {
        const { id, publicKey, encryptedPrivateKey, signinChallenge } = user;
        const encryptedChallenge = await encryptMessageAsymmetric(publicKey, signinChallenge);

        return response({ id, publicKey, encryptedPrivateKey, encryptedChallenge }, 200);
      }

      return response(httpErrorCodes.NOT_FOUND, 404);
    } catch (e) {
      console.log('get pubic user error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async signin(request) {
    const {
      body: { username, email, signinChallenge },
    } = parseRequest(request);

    try {
      const user = await getUser(username, email);
      if (!user) {
        return response(httpErrorCodes.BAD_REQUEST, 400);
      }

      const { id, signinChallenge: signinChallengeInDB, twoFactorEnabled, twoFactorChecked } = user;
      if (signinChallengeInDB !== signinChallenge) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      if (twoFactorEnabled) {
        const tempToken = tokenClient.generateTempToken(id);

        return response({ tempToken }, 200);
      }

      const tokens = await userClient.generateTokens(id);

      return response({ ...tokens, twoFactorChecked }, 200);
    } catch (e) {
      console.log('signin error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async verify2FA(request) {
    const {
      body: { tempToken, code },
    } = parseRequest(request);

    try {
      const decoded = tokenClient.verifyTempToken(tempToken);
      const userId = decoded.user;
      const isValidCode = await twoFactorClient.verifyCode(userId, code);
      if (!isValidCode) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      const tokens = await userClient.generateTokens(userId);

      return response(tokens, 200);
    } catch (e) {
      console.log('verify 2fa error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async refreshTokens(request) {
    const {
      body: { refreshToken },
    } = parseRequest(request);

    try {
      const decoded = tokenClient.verifyRefreshToken(refreshToken);

      await hasValidIssuedAt(decoded);

      const userId = decoded.user;
      const tokens = await userClient.generateTokens(userId);

      return response(tokens, 200);
    } catch (e) {
      return response(httpErrorCodes.UNAUTHORIZED, 401);
    }
  },

  async getUser(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    try {
      const user = await userClient.getByUserId(userId);

      if (!user) {
        return response(httpErrorCodes.NOT_FOUND, 404);
      }

      return response(
        {
          ...mapUser(user),
          backendPublicKey: process.env.BACKEND_PUBLIC_KEY,
        },
        200
      );
    } catch (e) {
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async changePassword(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);
    const {
      body: { encryptedPrivateKey, signinChallenge },
    } = parseRequest(request);

    try {
      const { signinChallenge: signinChallengeInDB } = await userClient.getByUserId(userId);

      if (signinChallengeInDB !== signinChallenge) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      const updatedUser = await userClient.updateEncryptedPrivateKey(userId, encryptedPrivateKey);

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      console.log('change password error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async skip2FA(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    try {
      const updatedUser = await userClient.skip2FA(userId);

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      console.log('skip 2fa error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async generate2FASecret(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    try {
      const user = await userClient.getByUserId(userId);
      if (!user) {
        return response(httpErrorCodes.NOT_FOUND, 404);
      }

      const uri = await twoFactorClient.generateSecret(user.username || user.email);

      return response({ uri }, 200);
    } catch (e) {
      console.log('generate 2fa secret error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async enable2FA(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);
    const {
      body: { code },
    } = parseRequest(request);

    try {
      const isValid = await twoFactorClient.verifyCode(userId, code);

      if (!isValid) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      const updatedUser = await userClient.enable2FA(userId);

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      console.log('enable 2fa error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async disable2FA(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);
    const {
      body: { code },
    } = parseRequest(request);

    try {
      const isValid = await twoFactorClient.verifyCode(userId, code);

      if (!isValid) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      const updatedUser = await userClient.disable2FA(userId);

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      console.log('disable 2fa error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async logoutFromAllDevices(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);
    try {
      const updatedUser = await userClient.logoutFromAllDevices(userId);

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async deleteUser(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    try {
      await userClient.deleteUser(userId);

      return response(
        {
          id: userId,
        },
        200
      );
    } catch (e) {
      console.log('delete user error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },
};
