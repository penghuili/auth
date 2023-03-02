import mapUser from '../dtos/mapUser';
import { encryptMessage } from '../shared/js/encryption';
import httpErrorCodes from '../shared/js/httpErrorCodes';
import hasValidIssuedAt from '../shared/node/hasValidIssuedAt';
import parseRequest from '../shared/node/parseRequest';
import response from '../shared/node/response';
import tokenClient from '../shared/node/tokenClient';
import userClient from '../shared/node/userClient';
import verifyAccessTokenMiddleware from '../shared/node/verifyAccessTokenMiddleware';
import telegramClient from '../shared/node/telegramClient';

const userController = {
  async signup(request) {
    const {
      body: { username, publicKey, encryptedPrivateKey },
    } = parseRequest(request);

    try {
      const existingUser = await userClient.getByUsername(username);
      if (existingUser) {
        return response(httpErrorCodes.ALREADY_EXISTS, 400);
      }

      const { id } = await userClient.create({
        username,
        publicKey,
        encryptedPrivateKey,
      });

      await telegramClient.sendMessage(
        process.env.ADMIN_TELEGRAM_ID,
        `Someone signed up :)`
      );

      return response({ id, username }, 200);
    } catch (e) {
      console.log('signup error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async getUserPublic(request) {
    const {
      pathParams: { username },
    } = parseRequest(request);

    try {
      const user = await userClient.getByUsername(username);
      if (user) {
        const { id, publicKey, encryptedPrivateKey, signinChallenge } = user;
        const encryptedChallenge = await encryptMessage(
          publicKey,
          signinChallenge
        );

        return response(
          { id, publicKey, encryptedPrivateKey, encryptedChallenge },
          200
        );
      }

      return response(httpErrorCodes.NOT_FOUND, 404);
    } catch (e) {
      console.log('get pubic user error', e);
      return response(httpErrorCodes.UNKNOWN, 400);
    }
  },

  async signin(request) {
    const {
      body: { username, signinChallenge },
    } = parseRequest(request);

    try {
      const user = await userClient.getByUsername(username);
      if (!user) {
        return response(httpErrorCodes.BAD_REQUEST, 400);
      }

      const { id, signinChallenge: signinChallengeInDB } = user;
      if (signinChallengeInDB !== signinChallenge) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      const accessToken = tokenClient.generateAccessToken(id);
      const refreshToken = tokenClient.generateRefreshToken(id);

      await userClient.refreshSigninChallenge(id);

      return response(
        {
          id,
          accessToken,
          refreshToken,
          expiresIn: +process.env.JWT_ACCESS_TOKEN_EXPIRES_IN,
        },
        200
      );
    } catch (e) {
      console.log('signin error', e);
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
      const newAccessToken = tokenClient.generateAccessToken(userId);
      const newRefreshToken = tokenClient.generateRefreshToken(userId);

      return response(
        {
          id: userId,
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          expiresIn: +process.env.JWT_ACCESS_TOKEN_EXPIRES_IN,
        },
        200
      );
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
      const { signinChallenge: signinChallengeInDB } =
        await userClient.getByUserId(userId);

      if (signinChallengeInDB !== signinChallenge) {
        return response(httpErrorCodes.FORBIDDEN, 403);
      }

      const updatedUser = await userClient.updateEncryptedPrivateKey(
        userId,
        encryptedPrivateKey
      );

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      console.log('change password error', e);
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

export default userController;
