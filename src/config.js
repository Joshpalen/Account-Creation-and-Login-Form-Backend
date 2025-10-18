const Joi = require('joi');
require('dotenv').config();

const schema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  // In test environment, provide a safe default so tests don't fail on missing env
  JWT_SECRET: Joi.alternatives().conditional('NODE_ENV', {
    is: 'test',
    then: Joi.string().min(10).default('test_jwt_secret_012345678901234567890'),
    otherwise: Joi.string().min(32).required(),
  }),
  DATABASE_URL: Joi.string().optional(),
  SMTP_HOST: Joi.string().optional(),
  SMTP_PORT: Joi.number().optional(),
  SMTP_USER: Joi.string().optional(),
  SMTP_PASS: Joi.string().optional(),
}).unknown();

const { error, value: env } = schema.validate(process.env);
if (error) {
  console.error('Config validation error:', error.message);
  throw new Error('Invalid configuration');
}

module.exports = env;
