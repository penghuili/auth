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

    const existingUser = await userClient.getByUsername(username);
    if (existingUser) {
      throw response(errorCodes.ALREADY_EXISTS, 400);
    }

    const { id } = await userClient.create({
      username,
      publicKey,
      encryptedPrivateKey,
    });

    return { id, username };
  },

  async getUserPublic(request) {
    const {
      pathParams: { username },
    } = parseRequest(request);
    const user = await userClient.getByUsername(username);
    if (user) {
      const { id, publicKey, encryptedPrivateKey, signinChallenge } = user;
      const encryptedChallenge = await cryptoClient.encryptMessage(
        publicKey,
        signinChallenge
      );

      return { id, publicKey, encryptedPrivateKey, encryptedChallenge };
    }

    throw response(errorCodes.NOT_FOUND, 404);
  },

  async signin(request) {
    const {
      body: { username, signinChallenge },
    } = parseRequest(request);

    const user = await userClient.getByUsername(username);
    if (!user) {
      throw response(errorCodes.BAD_REQUEST, 400);
    }

    const { id, signinChallenge: signinChallengeInDB } = user;
    if (signinChallengeInDB !== signinChallenge) {
      throw response(errorCodes.FORBIDDEN, 403);
    }

    const accessToken = tokenClient.generateAccessToken(id);
    const refreshToken = tokenClient.generateRefreshToken(id);

    await userClient.refreshSigninChallenge(id);

    return {
      id,
      accessToken,
      refreshToken,
      expiresIn: +process.env.JWT_ACCESS_TOKEN_EXPIRES_IN,
    };
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

      return {
        id: userId,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: +process.env.JWT_ACCESS_TOKEN_EXPIRES_IN,
      };
    } catch (e) {
      return response(errorCodes.UNAUTHORIZED, 401);
    }
  },

  async getUser(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    const user = await userClient.getByUserId(userId);

    if (!user) {
      return response(errorCodes.NOT_FOUND, 404);
    }

    return {
      ...mapUser(user),
      backendPublicKey: process.env.BACKEND_PUBLIC_KEY,
    };
  },

  async changePassword(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);
    const {
      body: { encryptedPrivateKey, signinChallenge },
    } = parseRequest(request);

    const { signinChallenge: signinChallengeInDB } =
      await userClient.getByUserId(userId);

    if (signinChallengeInDB !== signinChallenge) {
      throw response(errorCodes.FORBIDDEN, 403);
    }

    const updatedUser = await userClient.updateEncryptedPrivateKey(
      userId,
      encryptedPrivateKey
    );

    return mapUser(updatedUser);
  },

  async logoutFromAllDevices(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    const updatedUser = await userClient.logoutFromAllDevices(userId);

    return mapUser(updatedUser);
  },

  async deleteUser(request) {
    const { user: userId } = await verifyAccessTokenMiddleware(request);

    await userClient.deleteUser(userId);

    return {
      id: userId,
    };
  },
};

export default userController;
