const tokenClient = require('../clients/tokenClient');
const userClient = require('../clients/userClient');

const errorCodes = require('../lib/errorCodes');
const parseRequest = require('../lib/parseRequest');
const response = require('../lib/response');

async function verifyAccessTokenMiddleware(request) {
  const { headers } = parseRequest(request);

  const { authorization, Authorization } = headers || {};

  const authorizationHeader = Authorization || authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
    throw response(errorCodes.UNAUTHORIZED, 401);
  }

  const token = authorizationHeader.split(' ')[1];

  const decoded = tokenClient.verifyAccessToken(token);
  if (!decoded) {
    throw response(errorCodes.UNAUTHORIZED, 401);
  }

  const issuedAt = decoded.iat * 1000;
  const user = await userClient.getByUserId(decoded.user);
  if (!user || (user?.tokenValidFrom && issuedAt < user?.tokenValidFrom)) {
    throw response(errorCodes.UNAUTHORIZED, 401);
  }

  return decoded;
}

module.exports = verifyAccessTokenMiddleware;
