# auth API for peng.kiwi

## Your password is never saved in DB, even the hashed version

For normal websites, when you signup, you need to send your email and plaintext password to backend, then backend hashes the password and save it to DB.

Instead of doing that, I use [openpgpjs](https://github.com/openpgpjs/openpgpjs) to signup like this:

1. Generate a public and private keypair;
2. Encrypt the private key with your password;
3. Send your username, public key, encrypted private key to server;

Your password never leaves your device.

When you signin:

1. Your device makes a request with your username to get the public key, encrypted private key, and a random challenge encrypted with your public key on server;
2. Your device decrypts the encrypted private key;
3. Use the decrypted private key to decrypt the challenge;
4. Send the decrypted challenge to server;
5. Server checks is the challenge is solved, if yes, it will return an access token and a refresh token back to your device;

Btw, the endpoints are built with [claudiajs](https://www.claudiajs.com/)
