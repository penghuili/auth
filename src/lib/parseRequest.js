function parseRequest(request) {
  const { headers, pathParams, queryString, body, rawBody, locals } = request;
  return { headers, pathParams, queryString, body, rawBody, locals };
}

module.exports = parseRequest;
