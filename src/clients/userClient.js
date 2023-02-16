const dbClient = require('./dbClient');
const sortKeys = require('../lib/sortKeys');
const tokenClient = require('./tokenClient');

const userClient = {
  async create({ username, publicKey, encryptedPrivateKey }) {
    const id = tokenClient.uuid();
    const signinChallenge = tokenClient.uuid();
    const createdAt = Date.now();
    const user = {
      id,
      sortKey: sortKeys.user,
      username,
      publicKey,
      encryptedPrivateKey,
      signinChallenge,
      createdAt,
    };
    await dbClient.create(user);
    const usernameUser = {
      id: username,
      sortKey: sortKeys.user,
      userId: id,
    };
    await dbClient.create(usernameUser);

    return { id, username };
  },

  async getByUserId(userId) {
    const user = await dbClient.get(userId, sortKeys.user);

    return user;
  },

  async getByUsername(username) {
    const usernameUser = await dbClient.get(username, sortKeys.user);
    if (usernameUser) {
      const { userId } = usernameUser;
      const user = await userClient.getByUserId(userId);

      return user;
    }

    return null;
  },

  async refreshSigninChallenge(userId) {
    const user = await dbClient.get(userId, sortKeys.user);
    const updatedUser = await dbClient.update(userId, sortKeys.user, {
      ...user,
      signinChallenge: tokenClient.uuid(),
    });

    return updatedUser;
  },

  async updateEncryptedPrivateKey(userId, encryptedPrivateKey) {
    const user = await dbClient.get(userId, sortKeys.user);
    const updatedUser = await dbClient.update(userId, sortKeys.user, {
      ...user,
      encryptedPrivateKey,
      signinChallenge: tokenClient.uuid(),
      tokenValidFrom: Date.now(),
    });

    return updatedUser;
  },

  async logoutFromAllDevices(userId) {
    const user = await dbClient.get(userId, sortKeys.user);
    const updatedUser = await dbClient.update(userId, sortKeys.user, {
      ...user,
      tokenValidFrom: Date.now(),
    });

    return updatedUser;
  },

  async deleteUser(userId) {
    const user = await userClient.getByUserId(userId);
    await dbClient.delete(userId, sortKeys.user);
    await dbClient.delete(user.username, sortKeys.user);
  },
};

module.exports = userClient;
