require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/auth');
const config = require('./config');
const logger = require('./logger');
const knex = require('./db/knex');

const app = express();

// Security headers
app.use(helmet());

// CORS (allow all by default, configure in production)
app.use(cors());

// Basic rate limiting for auth routes
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json());
app.use('/auth', limiter, authRoutes);

// basic health check
app.get('/health', (req, res) => res.json({ ok: true }));

async function start() {
  try {
    if (process.env.NODE_ENV !== 'production') {
      // run migrations in dev/test automatically
      await knex.migrate.latest();
      logger.info('Migrations applied');
    }

    if (process.env.NODE_ENV !== 'test') {
      const port = config.PORT || 3000;
      app.listen(port, () => logger.info(`Server listening on ${port}`));
    }
  } catch (err) {
    logger.error('Startup error %o', err);
    process.exit(1);
  }
}

// Only auto-start when run directly (not when required by tests)
if (require.main === module) {
  start();
}

module.exports = { app, start };
