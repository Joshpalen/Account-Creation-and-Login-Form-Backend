require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const swaggerUI = require('swagger-ui-express');
const swaggerSpec = require('./swagger');
const authRoutes = require('./routes/auth');
const config = require('./config');
const logger = require('./logger');
const knex = require('./db/knex');
const adminUIRoutes = require('./routes/admin-ui');
const path = require('path');

const app = express();

// Security headers
app.use(helmet());

// CORS (allow all by default, configure in production)
app.use(cors());

// Swagger documentation
app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerSpec));

// Basic rate limiting for auth routes
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json());
app.use('/auth', limiter, authRoutes);
app.use('/totp', limiter, require('./routes/totp'));
app.use('/', adminUIRoutes);
// Serve static frontend
app.use(express.static(path.join(__dirname, '..', 'public')));
// default to index.html for root
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

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
