const { ApiResponse } = require('claudia-api-builder');

function response(data, httpCode, headers) {
  return new ApiResponse(data, headers, httpCode);
}

module.exports = response;
