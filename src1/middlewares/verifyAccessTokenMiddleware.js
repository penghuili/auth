import tokenClient from '../clients/tokenClient';
import hasValidIssuedAt from '../lib/hasValidIssuedAt';
import parseRequest from '../lib/parseRequest';
import response from '../lib/response';
import httpErrorCodes from '../shared/httpErrorCodes';

async function verifyAccessTokenMiddleware(request) {
  const { headers } = parseRequest(request);

  const { authorization, Authorization } = headers || {};

  const authorizationHeader = Authorization || authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
    throw response(httpErrorCodes.UNAUTHORIZED, 401);
  }

  const token = authorizationHeader.split(' ')[1];

  const decoded = tokenClient.verifyAccessToken(token);
  if (!decoded) {
    throw response(httpErrorCodes.UNAUTHORIZED, 401);
  }

  await hasValidIssuedAt(decoded);

  return decoded;
}

export default verifyAccessTokenMiddleware;
