# Account Creation and Login Backend

[![Node.js CI](https://github.com/Joshpalen/Account-Creation-and-Login-Form-Backend/actions/workflows/nodejs.yml/badge.svg)](https://github.com/Joshpalen/Account-Creation-and-Login-Form-Backend/actions/workflows/nodejs.yml)

Simple Express backend providing registration and login endpoints using SQLite, bcrypt and JWT.

Endpoints:
- POST /auth/register { email, password }
- POST /auth/login { email, password }
- GET /auth/verify?token=... (verify email)
- POST /auth/password-reset { email }
- POST /auth/password-reset/confirm { token, password }

Prerequisites:
- Node.js 18+ (LTS recommended)
- For production: PostgreSQL database
- For emails: SMTP server credentials

Development Setup:

```powershell
cd 'C:\Users\joshp\Desktop\Account Creation and Login Form Backend'
npm install
```

2. Copy `.env.example` to `.env` and set `JWT_SECRET`:

```powershell
copy .env.example .env
# edit .env and change JWT_SECRET to a secure value
```

3. Start the server:

```powershell
npm start
```

Run tests (locally):

```powershell
npm test
```

Continuous Integration:

There's a GitHub Actions workflow included that will install dependencies and run the test suite on push/PR.

Notes / Next steps:
- Add CORS configuration if the frontend is served from a different origin.
- Add rate-limiting and request validation.
- Use a persistent DB (Postgres) and migrations for production.

Docker
------
Build and run the service with Docker:

```powershell
docker build -t account-auth-backend .
docker run -p 3000:3000 --env JWT_SECRET=your_secret account-auth-backend
```

Or using docker-compose:

```powershell
docker compose up --build
```

Security & features included
- Helmet for basic security headers
- CORS enabled (configure origin in production)
- Rate limiting applied to `/auth` endpoints (20 requests/min)
- Input validation for register/login endpoints

## Admin Role Support

The backend now supports user roles. By default, all users are created with the `user` role. You can manually promote a user to `admin` in the database, or by using the `setRole` function in `src/db/users.js`.

### Admin-only Endpoint

- `GET /auth/admin` — Requires a valid JWT for a user with the `admin` role. Returns a welcome message if access is granted.

#### Example: Promoting a User to Admin (using Node REPL or script)

```js
const users = require('./src/db/users');
users.setRole(userId, 'admin');
```

#### Example: Accessing the Admin Endpoint

1. Login as an admin user to get a JWT token.
2. Make a request to `/auth/admin` with the token in the `Authorization` header:

```
Authorization: Bearer <your-admin-jwt>
```

If the user is not an admin, a 403 error is returned.

## Admin Management UI

Visit `/admin-ui` in your browser (with a valid admin JWT in localStorage as `token`) to:
- View all users
- Promote/demote users
- Delete users
- Edit user permissions (comma-separated, e.g. `canDeleteUsers,canBanUsers`)

## Permissions System

Each user can have a comma-separated list of permissions (e.g. `canDeleteUsers,canBanUsers`).

- Use the admin UI or the PATCH `/auth/admin/users/:id/permissions` endpoint to update permissions.
- Use the `requirePermission('permissionName')` middleware to protect routes by permission.

Example:
```js
const { requirePermission } = require('./middleware/auth');
app.get('/admin/special', requireAuth, requirePermission('canDeleteUsers'), (req, res) => { ... });
```


