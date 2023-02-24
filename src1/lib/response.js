import { ApiResponse } from 'claudia-api-builder';

function response(data, httpCode, headers) {
  return new ApiResponse(data, headers, httpCode);
}

export default response;
