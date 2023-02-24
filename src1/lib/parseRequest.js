function parseRequest(request) {
  const { headers, pathParams, queryString, body, rawBody, locals } = request;
  return { headers, pathParams, queryString, body, rawBody, locals };
}

export default parseRequest;
