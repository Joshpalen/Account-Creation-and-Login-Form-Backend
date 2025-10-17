const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const config = require('../config');
const logger = require('../logger');
const mailer = require('../mailer');
const users = require('../db/users');

const JWT_SECRET = config.JWT_SECRET;

function generateToken(payload, opts = {}) {
  return jwt.sign(payload, JWT_SECRET, opts);
}

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
      const { id } = await users.createUser({ email, passwordHash: hash, verificationToken });

      // send verification email (if mailer configured)
      const verifyLink = `${req.protocol}://${req.get('host')}/auth/verify?token=${verificationToken}`;
      await mailer.sendMail({
        to: email,
        subject: 'Verify your account',
        text: `Click to verify: ${verifyLink}`,
      });

      logger.info('User registered %s', email);
      return res.status(201).json({ id, email });
    } catch (err) {
      logger.error('register error: %o', err);
      return res.status(500).json({ error: 'internal error' });
    }
  }
);

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

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: 'invalid credentials' });

      const token = generateToken({ sub: user.id, email: user.email }, { expiresIn: '7d' });
      return res.json({ token });
    } catch (err) {
      logger.error('login error: %o', err);
      return res.status(500).json({ error: 'internal error' });
    }
  }
);

module.exports = router;
