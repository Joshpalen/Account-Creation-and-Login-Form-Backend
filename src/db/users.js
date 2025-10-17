async function deleteUser(id) {
  return knex('users').where({ id }).del();
}
async function listAll() {
  return knex('users').select('id', 'email', 'role', 'email_verified', 'permissions');
}
const knex = require('./knex');

async function createUser({ email, passwordHash, verificationToken=null, role='user', permissions='' }) {
  const [id] = await knex('users').insert({ email, password: passwordHash, email_verified: false, verification_token: verificationToken, role, permissions }).returning('id');
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
