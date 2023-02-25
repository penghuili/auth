import userClient from '../clients/userClient';
import httpErrorCodes from '../shared/httpErrorCodes';
import response from './response';

async function hasValidIssuedAt(decoded) {
  const issuedAt = decoded.iat * 1000;
  const user = await userClient.getByUserId(decoded.user);
  if (!user || (user?.tokenValidFrom && issuedAt < user?.tokenValidFrom)) {
    throw response(httpErrorCodes.UNAUTHORIZED, 401);
  }
}

export default hasValidIssuedAt;
