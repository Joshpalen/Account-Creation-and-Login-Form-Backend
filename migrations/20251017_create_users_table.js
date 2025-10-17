exports.up = function(knex) {
  return knex.schema.createTable('users', function(table) {
    table.increments('id').primary();
  table.string('email').unique().notNullable();
  table.string('password').notNullable();
  table.string('role').notNullable().defaultTo('user');
  table.boolean('email_verified').defaultTo(false);
  table.string('verification_token');
  table.string('reset_token');
    table.timestamps(true, true);
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('users');
};
