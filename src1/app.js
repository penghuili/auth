import ApiBuilder from 'claudia-api-builder';

import userController from './controllers/userController';

require('dotenv').config();

const api = new ApiBuilder();

api.get('/health', () => {
  return 'up';
});

// public
api.post('/v1/sign-up', userController.signup);
api.get('/v1/me-public/{username}', userController.getUserPublic);
api.post('/v1/sign-in', userController.signin);
api.post('/v1/sign-in/refresh', userController.refreshTokens);
api.post('/v1/log-out-all', userController.logoutFromAllDevices);

// protected
api.get('/v1/me', userController.getUser);
api.post('/v1/me/password', userController.changePassword);
api.delete('/v1/me', userController.deleteUser);

export default api;
