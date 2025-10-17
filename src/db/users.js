const knex = require('./knex');

async function deleteUser(id) {
  return knex('users').where({ id }).del();
}

async function listAll() {
  return knex('users').select('id', 'email', 'role', 'email_verified', 'permissions');
}

/**
 * Create a user and return { id }.
 * Knex .returning() behaves differently across DBs (Postgres returns [{id}] or [id],
 * sqlite may return the inserted id or nothing). Be defensive and normalize the result.
 */
async function createUser({ email, passwordHash, verificationToken = null, role = 'user', permissions = '' }) {
  const inserted = await knex('users')
    .insert({ email, password: passwordHash, email_verified: false, verification_token: verificationToken, role, permissions })
    .returning('id');

  let id;
  if (inserted === undefined || inserted === null) {
    // Some dialects (sqlite) may ignore .returning(); fetch by email as a fallback
    const row = await knex('users').where({ email }).first('id');
    id = row && (row.id || row.ID || row[Object.keys(row)[0]]);
  } else if (Array.isArray(inserted)) {
    const first = inserted[0];
    if (first && typeof first === 'object') id = first.id || first.ID || Object.values(first)[0];
    else id = first;
  } else if (typeof inserted === 'object') {
    id = inserted.id || inserted.ID || Object.values(inserted)[0];
  } else {
    id = inserted;
  }

  return { id };
}

async function findByEmail(email) {
  return knex('users').where({ email }).first();
}

async function findById(id) {
  return knex('users').where({ id }).first();
}

async function setEmailVerified(id) {
  return knex('users').where({ id }).update({ email_verified: true, verification_token: null });
}

async function setResetToken(email, token) {
  return knex('users').where({ email }).update({ reset_token: token });
}

async function updatePassword(id, passwordHash) {
  return knex('users').where({ id }).update({ password: passwordHash, reset_token: null });
}

async function setRole(id, role) {
  return knex('users').where({ id }).update({ role });
}

async function setPermissions(id, permissions) {
  return knex('users').where({ id }).update({ permissions });
}

module.exports = { createUser, findByEmail, findById, setEmailVerified, setResetToken, updatePassword, setRole, setPermissions, listAll, deleteUser };
