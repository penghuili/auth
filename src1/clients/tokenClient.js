import jsonwebtoken from 'jsonwebtoken';
import ShortId from 'short-unique-id';
import { v4 as uuidV4 } from 'uuid';

import response from '../lib/response';
import httpErrorCodes from '../shared/httpErrorCodes';

const sid = new ShortId({ length: 11 });

const tokenClient = {
  generateAccessToken(userId) {
    return jsonwebtoken.sign(
      { issuer: 'peng.kiwi', user: userId },
      process.env.JWT_ACCESS_TOKEN_SECRET,
      {
        expiresIn: +process.env.JWT_ACCESS_TOKEN_EXPIRES_IN,
      }
    );
  },
  verifyAccessToken(accessToken) {
    try {
      const decoded = jsonwebtoken.verify(
        accessToken,
        process.env.JWT_ACCESS_TOKEN_SECRET
      );
      return decoded;
    } catch (error) {
      return null;
    }
  },
  generateRefreshToken(userId) {
    return jsonwebtoken.sign(
      { issuer: 'peng.kiwi', user: userId },
      process.env.JWT_REFRESH_TOKEN_SECRET,
      {
        expiresIn: +process.env.JWT_REFRESH_TOKEN_EXPIRES_IN,
      }
    );
  },
  verifyRefreshToken(refreshToken) {
    try {
      const decoded = jsonwebtoken.verify(
        refreshToken,
        process.env.JWT_REFRESH_TOKEN_SECRET
      );
      return decoded;
    } catch (error) {
      throw response(httpErrorCodes.UNAUTHORIZED, 401);
    }
  },
  uuid() {
    return uuidV4();
  },
  shortId() {
    return sid();
  },
};

export default tokenClient;
