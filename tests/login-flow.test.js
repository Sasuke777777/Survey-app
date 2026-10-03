const assert = require('assert');
const bcrypt = require('bcryptjs');
const { generate, generateSecret } = require('otplib');
const authController = require('../controllers/authControllers');

(async () => {
  const originalGmailUser = process.env.GMAIL_USER;
  const originalGmailPassword = process.env.GMAIL_APP_PASSWORD;
  const user = { id: 7, username: 'demo', email: 'demo@example.com', password: await bcrypt.hash('secretpass', 12) };
  let secret;
  let mfaEnabled = false;
  delete process.env.GMAIL_USER;
  delete process.env.GMAIL_APP_PASSWORD;

  const fakeDb = {
    promise() {
      return {
        async query(sql, params) {
          if (sql.includes('SELECT * FROM users')) {
            return [[user]];
          }
          if (sql.includes('SELECT enabled FROM user_mfa')) {
            return [mfaEnabled ? [{ enabled: true }] : []];
          }
          if (sql.includes('SELECT secret FROM user_mfa')) {
            return [mfaEnabled ? [{ secret }] : []];
          }
          if (sql.includes('INSERT INTO user_mfa')) {
            secret = params[1];
            mfaEnabled = false;
            return [{ affectedRows: 1 }];
          }
          if (sql.includes('SELECT secret, enabled FROM user_mfa')) {
            return [secret ? [{ secret, enabled: mfaEnabled }] : []];
          }
          if (sql.includes('UPDATE user_mfa SET enabled')) {
            mfaEnabled = true;
            return [{ affectedRows: 1 }];
          }
          if (sql.includes('SELECT id, username, email FROM users')) {
            return [[{ id: user.id, username: user.username, email: user.email }]];
          }
          if (sql.includes('DELETE FROM login_otps')) {
            return [{ affectedRows: 1 }];
          }
          if (sql.includes('INSERT INTO login_otps')) {
            return [{ insertId: 1 }];
          }
          return [[]];
        }
      };
    }
  };

  authController.setDatabase(fakeDb);

  let statusCode = null;
  let jsonPayload = null;
  const req = { body: { email: 'demo@example.com', password: 'secretpass' } };
  const res = {
    status(code) { statusCode = code; return this; },
    json(payload) { jsonPayload = payload; return this; }
  };

  await authController.loginUser(req, res);

  assert.ok(statusCode === null || statusCode === undefined, 'should not respond with an error status in dev mode');
  assert.ok(jsonPayload && jsonPayload.requiresOtp, 'should return OTP challenge when Gmail is not configured');
  assert.ok(jsonPayload.challengeId, 'should include challenge ID');
  assert.ok(jsonPayload.code, 'should include a usable code in local/dev mode');

  statusCode = null;
  jsonPayload = null;
  await authController.setupMfa({ user: { id: user.id, email: user.email } }, res);
  assert.ok(jsonPayload.qrDataUrl.startsWith('data:image/png;base64,'), 'enrollment should return a QR code');
  assert.ok(secret, 'enrollment should create a TOTP secret');

  statusCode = null;
  jsonPayload = null;
  await authController.verifyMfaSetup({ user: { id: user.id }, body: { code: await generate({ secret }) } }, res);
  assert.strictEqual(mfaEnabled, true, 'a valid TOTP should enable authenticator sign-in');

  statusCode = null;
  jsonPayload = null;
  await authController.loginUser(req, res);
  assert.strictEqual(jsonPayload.method, 'authenticator', 'enabled accounts should require an authenticator code');
  assert.ok(!jsonPayload.code, 'authenticator codes must not be returned by the server');

  const challengeId = jsonPayload.challengeId;
  statusCode = null;
  jsonPayload = null;
  await authController.verifyLoginOtp({ body: { challengeId, code: await generate({ secret }) } }, res);
  assert.ok(jsonPayload.token, 'a valid authenticator code should finish sign-in');

  statusCode = null;
  jsonPayload = null;
  await authController.verifyLoginOtp({ body: { challengeId, code: '000000' } }, res);
  assert.strictEqual(statusCode, 401, 'an invalid authenticator code should be rejected');

  const originalNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  mfaEnabled = false;
  statusCode = null;
  jsonPayload = null;
  await authController.loginUser(req, res);
  assert.strictEqual(statusCode, 500, 'production sign-in must fail closed without email delivery');
  assert.ok(!jsonPayload.code, 'production sign-in must not expose an email code');
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;

  process.env.GMAIL_USER = originalGmailUser;
  process.env.GMAIL_APP_PASSWORD = originalGmailPassword;
  console.log('login-flow test passed');
})();
