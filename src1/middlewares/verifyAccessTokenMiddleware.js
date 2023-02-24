import tokenClient from '../clients/tokenClient';
import userClient from '../clients/userClient';
import errorCodes from '../lib/errorCodes';
import parseRequest from '../lib/parseRequest';
import response from '../lib/response';

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

export default verifyAccessTokenMiddleware;
