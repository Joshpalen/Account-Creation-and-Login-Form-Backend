# Account Creation and Login Backend

[![Node.js CI](https://github.com/Joshpalen/Account-Creation-and-Login-Form-Backend/actions/workflows/nodejs.yml/badge.svg)](https://github.com/Joshpalen/Account-Creation-and-Login-Form-Backend/actions/workflows/nodejs.yml)

Simple Express backend providing registration and login with email verification, password reset, optional 2FA (TOTP), role/permission-based admin endpoints, and a lightweight admin UI. Uses Express, Knex, SQLite (dev/test), and JWT.

Key Endpoints
- `POST /auth/register` { email, password }
- `POST /auth/login` { email, password }
- `GET /auth/verify?token=...` (verify email)
- `POST /auth/password-reset` { email }
- `POST /auth/password-reset/confirm` { token, password }
- `POST /totp/setup` (auth) – start TOTP setup, returns otpauth URL + base32
- `POST /totp/verify` { token } (auth) – verify TOTP and enable 2FA
- `POST /totp/disable` (auth) – disable 2FA
- `GET /auth/admin` (admin)
- `PATCH /auth/admin/users/:id/role` (admin)
- `PATCH /auth/admin/users/:id/permissions` (admin)
- `DELETE /auth/admin/users/:id` (admin)

Prerequisites
- Node.js 18+ (LTS recommended)
- For production: PostgreSQL database (dev/test use SQLite)
- For emails: SMTP server credentials (optional)

Development Setup
1) Install dependencies
```
npm install
```

2) Environment
Copy `.env.example` to `.env` and set values. Minimum required is `JWT_SECRET` in non-test environments.
```
PORT=3000
JWT_SECRET=change_this_to_a_secure_value
# Optional:
DATABASE_URL=
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=
```

3) Start the server
```
npm start
```

4) Run tests
```
npm test
```

Swagger UI is available at `/api-docs` when the server is running.

Docker
------
Build and run the service with Docker:
```
docker build -t account-auth-backend .
docker run -p 3000:3000 --env JWT_SECRET=your_secret account-auth-backend
```

Or using docker-compose:
```
docker compose up --build
```

Security & Features
- Helmet for basic security headers
- CORS enabled (configure origin in production)
- Rate limiting applied to `/auth` endpoints (20 requests/min)
- Input validation for register/login endpoints
- Optional TOTP 2FA endpoints
- Swagger docs at `/api-docs`

Admin Role Support
- By default, users are created with role `user`.
- Promote a user to `admin` in the DB or via `setRole` from `src/db/users.js`.

Admin-only Endpoint
- `GET /auth/admin` — requires a valid JWT with role `admin`.

Promote a User to Admin (Node REPL or script)
```js
const users = require('./src/db/users');
users.setRole(userId, 'admin');
```

Permissions System
- Each user can have a comma-separated list of permissions (e.g. `canDeleteUsers,canBanUsers`).
- Use the admin UI or `PATCH /auth/admin/users/:id/permissions` to update permissions.
- Use `requirePermission('permissionName')` to protect routes.

Example
```js
const { requireAuth, requirePermission } = require('./src/middleware/auth');
app.get('/admin/special', requireAuth, requirePermission('canDeleteUsers'), (req, res) => { /* ... */ });
```

