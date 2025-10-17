const knex = require('./knex');

async function createUser({ email, passwordHash, verificationToken=null }) {
  const [id] = await knex('users').insert({ email, password: passwordHash, email_verified: false, verification_token: verificationToken }).returning('id');
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

module.exports = { createUser, findByEmail, findById, setEmailVerified, setResetToken, updatePassword };
