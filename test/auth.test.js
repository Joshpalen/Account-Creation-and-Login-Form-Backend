const request = require('supertest');
process.env.NODE_ENV = 'test'; // ensure tests use the test config

// mock mailer so tests don't send real emails and we can assert calls
jest.mock('../src/mailer', () => ({ sendMail: jest.fn().mockResolvedValue(true), sendTemplate: jest.fn().mockResolvedValue(true), renderTemplate: jest.fn().mockReturnValue({ text: 't', html: '<p>h</p>' }) }));
const mailer = require('../src/mailer');

const knex = require('../src/db/knex');
let app;

beforeAll(async () => {
  await knex.migrate.latest();
  // require app after migrations to avoid concurrent migration runs
  const server = require('../src/index');
  app = server.app;
});

afterEach(async () => {
  await knex('users').del();
});

afterAll(async () => {
  await knex.destroy();
});

describe('auth', () => {
  test('registers a user', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'a@b.com', password: 'password' })
      .expect(201);

    expect(res.body).toHaveProperty('id');
    expect(res.body.email).toBe('a@b.com');
  });

  test('register sends verification email', async () => {
    mailer.sendMail.mockClear();
    await request(app).post('/auth/register').send({ email: 'm@m.com', password: 'password' }).expect(201);
    expect(mailer.sendMail).toHaveBeenCalled();
  });

  test('verify email flow', async () => {
    // register
    await request(app).post('/auth/register').send({ email: 'v@v.com', password: 'password' }).expect(201);
    // read verification token from DB
    const row = await knex('users').where({ email: 'v@v.com' }).first();
    expect(row).toBeDefined();
    const token = row.verification_token;
    expect(token).toBeTruthy();

    // verify
    const res = await request(app).get('/auth/verify').query({ token }).expect(200);
    expect(res.body).toEqual({ ok: true });
    const updated = await knex('users').where({ email: 'v@v.com' }).first();
    expect(updated.email_verified).toBe(1 || true);
  });

  test('register validation fails on short password', async () => {
    const res = await request(app).post('/auth/register').send({ email: 'b@b.com', password: '1' }).expect(400);
    expect(res.body).toHaveProperty('errors');
  });

  test('prevents duplicate register', async () => {
    await request(app).post('/auth/register').send({ email: 'a@b.com', password: 'securepass' }).expect(201);
    await request(app).post('/auth/register').send({ email: 'a@b.com', password: 'securepass' }).expect(409);
  });

  test('login returns token (after verification)', async () => {
    await request(app).post('/auth/register').send({ email: 'x@y.com', password: 'secure123' }).expect(201);
    // verify email first
    const row = await knex('users').where({ email: 'x@y.com' }).first();
    const token = row.verification_token;
    await request(app).get('/auth/verify').query({ token }).expect(200);
    const res = await request(app).post('/auth/login').send({ email: 'x@y.com', password: 'secure123' }).expect(200);
    expect(res.body).toHaveProperty('token');
  });

  test('login validation fails with invalid email', async () => {
    const res = await request(app).post('/auth/login').send({ email: 'not-an-email', password: 'secure' }).expect(400);
    expect(res.body).toHaveProperty('errors');
  });

  test('health check', async () => {
    const res = await request(app).get('/health').expect(200);
    expect(res.body).toEqual({ ok: true });
  });

  test('login fails with wrong password', async () => {
    await request(app).post('/auth/register').send({ email: 'z@z.com', password: 'correct' }).expect(201);
    await request(app).post('/auth/login').send({ email: 'z@z.com', password: 'wrong' }).expect(401);
  });

  test('password reset flow', async () => {
    // register
    await request(app).post('/auth/register').send({ email: 'r@r.com', password: 'password' }).expect(201);
    // request reset
    mailer.sendMail.mockClear();
    await request(app).post('/auth/password-reset').send({ email: 'r@r.com' }).expect(200);
    expect(mailer.sendMail).toHaveBeenCalled();
    // read token
    const row = await knex('users').where({ email: 'r@r.com' }).first();
    expect(row.reset_token).toBeTruthy();
    const token = row.reset_token;
    // confirm reset
    await request(app).post('/auth/password-reset/confirm').send({ token, password: 'newpass' }).expect(200);
    // verify email before login
    const verifyToken = (await knex('users').where({ email: 'r@r.com' }).first()).verification_token;
    await request(app).get('/auth/verify').query({ token: verifyToken }).expect(200);
    // login with new password
    await request(app).post('/auth/login').send({ email: 'r@r.com', password: 'newpass' }).expect(200);
  });
});
