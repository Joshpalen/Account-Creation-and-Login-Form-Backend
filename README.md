# Account Creation and Login Backend

Simple Express backend providing registration and login endpoints using SQLite, bcrypt and JWT.

Endpoints:
- POST /auth/register { email, password }
- POST /auth/login { email, password }

Run locally:

1. Install Node.js (if needed) and dependencies:

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

Next improvements
- Add email verification and password reset flow
- Replace SQLite with Postgres and add migrations
- Add logging and structured error handling
- Add HTTPS, stronger secrets handling (secrets manager)


