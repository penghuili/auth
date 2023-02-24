import cryptoClient from '../clients/cryptoClient';
import tokenClient from '../clients/tokenClient';
import userClient from '../clients/userClient';
import mapUser from '../dtos/mapUser';
import errorCodes from '../lib/errorCodes';
import parseRequest from '../lib/parseRequest';
import response from '../lib/response';
import verifyAccessTokenMiddleware from '../middlewares/verifyAccessTokenMiddleware';

const userController = {
  async signup(request) {
    const {
      body: { username, publicKey, encryptedPrivateKey },
    } = parseRequest(request);

    try {
      const existingUser = await userClient.getByUsername(username);
      if (existingUser) {
        return response(errorCodes.ALREADY_EXISTS, 400);
      }

      const { id } = await userClient.create({
        username,
        publicKey,
        encryptedPrivateKey,
      });

      return response({ id, username }, 200);
    } catch (e) {
      return response(errorCodes.UNKNOWN, 400);
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
        const encryptedChallenge = await cryptoClient.encryptMessage(
          publicKey,
          signinChallenge
        );

        return response(
          { id, publicKey, encryptedPrivateKey, encryptedChallenge },
          200
        );
      }

      return response(errorCodes.NOT_FOUND, 404);
    } catch (e) {
      console.log('get pubic user error', e);
      return response(errorCodes.UNKNOWN, 400);
    }
  },

  async signin(request) {
    const {
      body: { username, signinChallenge },
    } = parseRequest(request);

    try {
      const user = await userClient.getByUsername(username);
      if (!user) {
        return response(errorCodes.BAD_REQUEST, 400);
      }

      const { id, signinChallenge: signinChallengeInDB } = user;
      if (signinChallengeInDB !== signinChallenge) {
        return response(errorCodes.FORBIDDEN, 403);
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
      return response(errorCodes.UNKNOWN, 400);
    }
  },

  async refreshTokens(request) {
    const {
      body: { refreshToken },
    } = parseRequest(request);

    try {
      const decoded = tokenClient.verifyRefreshToken(refreshToken);

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
      return response(errorCodes.UNAUTHORIZED, 401);
    }
  },

  async getUser(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    try {
      const user = await userClient.getByUserId(userId);

      if (!user) {
        return response(errorCodes.NOT_FOUND, 404);
      }

      return response(
        {
          ...mapUser(user),
          backendPublicKey: process.env.BACKEND_PUBLIC_KEY,
        },
        200
      );
    } catch (e) {
      return response(errorCodes.UNKNOWN, 400);
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
        return response(errorCodes.FORBIDDEN, 403);
      }

      const updatedUser = await userClient.updateEncryptedPrivateKey(
        userId,
        encryptedPrivateKey
      );

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      return response(errorCodes.UNKNOWN, 400);
    }
  },

  async logoutFromAllDevices(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);
    try {
      const updatedUser = await userClient.logoutFromAllDevices(userId);

      return response(mapUser(updatedUser), 200);
    } catch (e) {
      return response(errorCodes.UNKNOWN, 400);
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
      return response(errorCodes.UNKNOWN, 400);
    }
  },
};

export default userController;
