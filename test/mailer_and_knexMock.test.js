jest.mock('../src/db/knex', () => {
  // simulate a knex factory function where insert().returning() returns an array of strings
  return jest.fn(() => ({
    insert: () => ({ returning: () => ['42'] }),
    where: () => ({ first: () => ({ id: 42 }) }),
  }));
});

const mailer = require('../src/mailer');
const users = require('../src/db/users');

describe('mailer templates and knex returning shapes', () => {
  test('render verify template', () => {
    const out = mailer.renderTemplate('verify', { email: 'a@b.com', verifyLink: 'http://x' });
    expect(out.text).toContain('Please verify your account');
    expect(out.html).toContain('<a href="http://x">here</a>');
  });

  test('createUser handles mocked returning shapes', async () => {
    const res = await users.createUser({ email: `m-${Date.now()}@ex.com`, passwordHash: 'pw' });
    expect(res).toBeDefined();
    expect(res.id).toBeTruthy();
  });
});
