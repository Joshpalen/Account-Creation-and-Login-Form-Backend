const users = require('../src/db/users');
const knex = require('../src/db/knex');

beforeAll(async () => {
  // Ensure migrations are up
  await knex.migrate.latest();
});

afterAll(async () => {
  await knex.destroy();
});

describe('createUser normalization', () => {
  test('createUser returns an object with id and user is persisted', async () => {
    const email = `test-${Date.now()}@example.com`;
    const pw = 'password123';
    const res = await users.createUser({ email, passwordHash: pw });
    expect(res).toBeDefined();
    expect(res.id).toBeTruthy();

    const u = await users.findById(res.id);
    expect(u).toBeDefined();
    expect(u.email).toBe(email);
  });
});
