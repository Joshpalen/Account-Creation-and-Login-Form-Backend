const request = require('supertest');
const speakeasy = require('speakeasy');
const knex = require('../src/db/knex');
let app;

beforeAll(async () => {
  await knex.migrate.latest();
  const server = require('../src/index');
  app = server.app;
});

afterEach(async () => {
  await knex('users').del();
});

afterAll(async () => {
  await knex.destroy();
});

describe('2FA TOTP endpoints', () => {
  let token;
  let userId;
  beforeEach(async () => {
    // Register and login to get JWT
    await request(app).post('/auth/register').send({ email: '2fa@x.com', password: 'pw12345' }).expect(201);
    // Verify email before login
    const verifyRow = await knex('users').where({ email: '2fa@x.com' }).first();
    const verifyToken = verifyRow.verification_token;
    await request(app).get('/auth/verify').query({ token: verifyToken }).expect(200);
    const res = await request(app).post('/auth/login').send({ email: '2fa@x.com', password: 'pw12345' }).expect(200);
    token = res.body.token;
    const row = await knex('users').where({ email: '2fa@x.com' }).first();
    userId = row.id;
  });

  test('setup returns otpauth url and base32', async () => {
    const res = await request(app)
      .post('/totp/setup')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(res.body.otpauth_url).toContain('otpauth://');
    expect(res.body.base32).toBeTruthy();
  });

  test('verify enables 2FA', async () => {
    // Setup
    const setupRes = await request(app)
      .post('/totp/setup')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const secret = setupRes.body.base32;
    // Generate valid TOTP code
    const code = speakeasy.totp({ secret, encoding: 'base32' });
    // Verify
    const verifyRes = await request(app)
      .post('/totp/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ token: code })
      .expect(200);
    expect(verifyRes.body.ok).toBe(true);
    // Check DB
    const row = await knex('users').where({ id: userId }).first();
    expect(row.totp_enabled).toBe(1 || true);
  });

  test('disable disables 2FA', async () => {
    // Setup and enable
    const setupRes = await request(app)
      .post('/totp/setup')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const secret = setupRes.body.base32;
    const code = speakeasy.totp({ secret, encoding: 'base32' });
    await request(app)
      .post('/totp/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({ token: code })
      .expect(200);
    // Disable
    const disableRes = await request(app)
      .post('/totp/disable')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(disableRes.body.ok).toBe(true);
    // Check DB
    const row = await knex('users').where({ id: userId }).first();
    // SQLite stores booleans as integers (0/1); accept falsy
    expect(row.totp_enabled).toBeFalsy();
    expect(row.totp_secret).toBeFalsy();
  });
});
