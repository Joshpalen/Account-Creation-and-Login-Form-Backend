const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const config = require('../config');
const logger = require('../logger');
const mailer = require('../mailer');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const users = require('../db/users');

// ... admin permissions route moved below after imports to fix initialization order
/**
 * @swagger
 * /auth/admin/users/{id}/role:
 *   patch:
 *     summary: Change a user's role (admin only)
 *     description: Promote or demote a user by changing their role. Admin access required.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - role
 *             properties:
 *               role:
 *                 type: string
 *                 example: admin
 *     responses:
 *       200:
 *         description: User role updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *       400:
 *         description: Invalid role
 *       403:
 *         description: Admin access required
 *       404:
 *         description: User not found
 */
router.patch('/admin/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'invalid role' });
  const user = await users.findById(id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  await users.setRole(id, role);
  res.json({ ok: true });
});

router.patch('/admin/users/:id/permissions', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { permissions } = req.body;
  const user = await users.findById(id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  await users.setPermissions(id, permissions);
  res.json({ ok: true });
});

/**
 * @swagger
 * /auth/admin/users/{id}:
 *   delete:
 *     summary: Delete a user (admin only)
 *     description: Delete a user by ID. Admin access required.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: User ID
 *     responses:
 *       200:
 *         description: User deleted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *       403:
 *         description: Admin access required
 *       404:
 *         description: User not found
 */
router.delete('/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const user = await users.findById(id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  await users.deleteUser(id);
  res.json({ ok: true });
});
/**
 * @swagger
 * /auth/admin/users:
 *   get:
 *     summary: List all users (admin only)
 *     description: Returns a list of all users. Admin access required.
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   email:
 *                     type: string
 *                   role:
 *                     type: string
 *                   email_verified:
 *                     type: boolean
 *       403:
 *         description: Admin access required
 */
router.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const allUsers = await users.listAll();
  res.json(allUsers);
});
/**
 * @swagger
 * /auth/admin:
 *   get:
 *     summary: Admin-only endpoint
 *     description: Returns a message only if the user is an admin
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Admin access granted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Welcome, admin!
 *       403:
 *         description: Admin access required
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.json({ message: 'Welcome, admin!' });
});

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address
 *           example: user@example.com
 *         password:
 *           type: string
 *           format: password
 *           description: User's password (min 6 characters)
 *           example: mySecurePassword123
 *     AuthResponse:
 *       type: object
 *       properties:
 *         token:
 *           type: string
 *           description: JWT token for authentication
 *           example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *         message:
 *           type: string
 *           description: Response message
 *           example: Successfully logged in
 *     ErrorResponse:
 *       type: object
 *       properties:
 *         error:
 *           type: string
 *           description: Error message
 *           example: Invalid credentials
 *     PasswordResetRequest:
 *       type: object
 *       required:
 *         - email
 *       properties:
 *         email:
 *           type: string
 *           format: email
 *           description: Email address for password reset
 *           example: user@example.com
 *     NewPassword:
 *       type: object
 *       required:
 *         - password
 *       properties:
 *         password:
 *           type: string
 *           format: password
 *           description: New password (min 6 characters)
 *           example: newSecurePassword123
 */

const JWT_SECRET = config.JWT_SECRET;

function generateToken(payload, opts = {}) {
  return jwt.sign(payload, JWT_SECRET, opts);
}

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user account and sends verification email
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Verification email sent
 *       400:
 *         description: Invalid input
 *       409:
 *         description: Email already registered
 */
router.post('/register',
  body('email').isEmail().withMessage('valid email required'),
  body('password').isLength({ min: 6 }).withMessage('password must be >= 6 chars'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body || {};
    try {
      const existing = await users.findByEmail(email);
      if (existing) return res.status(409).json({ error: 'email already exists' });

      const hash = await bcrypt.hash(password, 10);
      const verificationToken = generateToken({ email }, { expiresIn: '1d' });
      const createdResult = await users.createUser({ email, passwordHash: hash, verificationToken });
      let id = createdResult && (createdResult.id || createdResult.ID || createdResult);

      // send verification email (if mailer configured)
      const verifyLink = `${req.protocol}://${req.get('host')}/auth/verify?token=${verificationToken}`;
      await mailer.sendMail({
        to: email,
        subject: 'Verify your account',
        text: `Click to verify: ${verifyLink}`,
      });
      if (!id) {
        logger.error('createUser did not return an id, result=%o', createdResult);
        return res.status(500).json({ error: 'internal error' });
      }

      logger.info('User registered %s', email);
      const created = await users.findById(id);
      const token = generateToken({ sub: created.id, email: created.email, role: created.role, permissions: created.permissions || '' }, { expiresIn: '7d' });
      return res.status(201).json({ id, email, token });
    } catch (err) {
      logger.error('register error: %o', err);
      return res.status(500).json({ error: 'internal error' });
    }
  }
);

/**
 * @swagger
 * /auth/verify:
 *   get:
 *     summary: Verify email address
 *     description: Verifies a user's email address using the token sent in the verification email
 *     tags: [Authentication]
 *     parameters:
 *       - in: query
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Email verification token
 *         example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *     responses:
 *       200:
 *         description: Email verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Email verified successfully
 *       400:
 *         description: Invalid or expired token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get('/verify', async (req, res) => {
  const { token } = req.query || {};
  if (!token) return res.status(400).json({ error: 'missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await users.findByEmail(payload.email);
    if (!user) return res.status(404).json({ error: 'user not found' });
    await users.setEmailVerified(user.id);
    return res.json({ ok: true });
  } catch (err) {
    logger.error('verify error %o', err);
    return res.status(400).json({ error: 'invalid or expired token' });
  }
});

/**
 * @swagger
 * /auth/password-reset:
 *   post:
 *     summary: Request password reset
 *     description: Sends a password reset email with a reset token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/PasswordResetRequest'
 *     responses:
 *       200:
 *         description: Reset email sent (returns OK even if email doesn't exist for security)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *       400:
 *         description: Invalid email format
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/password-reset',
  body('email').isEmail().withMessage('valid email required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email } = req.body;
    try {
      const user = await users.findByEmail(email);
      if (!user) return res.status(200).json({ ok: true }); // don't reveal existence
      const token = generateToken({ sub: user.id }, { expiresIn: '1h' });
      await users.setResetToken(email, token);
      const resetLink = `${req.protocol}://${req.get('host')}/auth/password-reset/confirm?token=${token}`;
      await mailer.sendMail({ to: email, subject: 'Password reset', text: `Reset: ${resetLink}` });
      return res.json({ ok: true });
    } catch (err) {
      logger.error('password-reset error %o', err);
      return res.status(500).json({ error: 'internal error' });
    }
  }
);

/**
 * @swagger
 * /auth/password-reset/confirm:
 *   post:
 *     summary: Confirm password reset
 *     description: Reset password using the token received in email
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - password
 *             properties:
 *               token:
 *                 type: string
 *                 description: Password reset token received via email
 *                 example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *               password:
 *                 type: string
 *                 format: password
 *                 description: New password (min 6 characters)
 *                 example: newSecurePassword123
 *     responses:
 *       200:
 *         description: Password reset successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *       400:
 *         description: Invalid token or password
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post('/password-reset/confirm',
  body('token').notEmpty(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { token, password } = req.body;
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const user = await users.findById(payload.sub);
      if (!user || user.reset_token !== token) return res.status(400).json({ error: 'invalid token' });
      const hash = await bcrypt.hash(password, 10);
      await users.updatePassword(user.id, hash);
      return res.json({ ok: true });
    } catch (err) {
      logger.error('password-reset-confirm error %o', err);
      return res.status(400).json({ error: 'invalid or expired token' });
    }
  }
);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Authenticate a user
 *     description: Login with email and password to receive a JWT token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/AuthResponse'
 *       400:
 *         description: Invalid credentials
 *       401:
 *         description: Email not verified
 */
router.post('/login',
  body('email').isEmail().withMessage('valid email required'),
  body('password').notEmpty().withMessage('password required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body || {};
    try {
      const user = await users.findByEmail(email);
      if (!user) return res.status(401).json({ error: 'invalid credentials' });

      // Require verified email before issuing tokens
      if (!user.email_verified) return res.status(401).json({ error: 'email not verified' });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  const token = generateToken({ sub: user.id, email: user.email, role: user.role, permissions: user.permissions || '' }, { expiresIn: '7d' });
      return res.json({ token });
    } catch (err) {
      logger.error('login error: %o', err);
      return res.status(500).json({ error: 'internal error' });
    }
  }
);

module.exports = router;
