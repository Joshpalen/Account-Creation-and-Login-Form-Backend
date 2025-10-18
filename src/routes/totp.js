const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const users = require('../db/users');
const { requireAuth } = require('../middleware/auth');

/**
 * @swagger
 * /totp/setup:
 *   post:
 *     summary: Start 2FA TOTP setup
 *     description: Generates a TOTP secret and returns an otpauth URL and base32 secret. Requires auth.
 *     tags: [TOTP]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: TOTP secret generated
 *       401:
 *         description: Unauthorized
 */
// POST /totp/setup - generate secret and return otpauth URL
router.post('/setup', requireAuth, async (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20, name: `App (${req.user.email})` });
  await users.setTotpSecret(req.user.id, secret.base32);
  res.json({ otpauth_url: secret.otpauth_url, base32: secret.base32 });
});

/**
 * @swagger
 * /totp/verify:
 *   post:
 *     summary: Verify TOTP code
 *     description: Verifies the TOTP token and enables 2FA. Requires auth.
 *     tags: [TOTP]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA enabled
 *       400:
 *         description: No secret setup
 *       401:
 *         description: Invalid code or unauthorized
 */
// POST /totp/verify - verify TOTP code and enable 2FA
router.post('/verify', requireAuth, async (req, res) => {
  const { token } = req.body;
  const secret = await users.getTotpSecret(req.user.id);
  if (!secret) return res.status(400).json({ error: 'no secret setup' });
  const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token });
  if (!verified) return res.status(401).json({ error: 'invalid code' });
  await users.enableTotp(req.user.id);
  res.json({ ok: true });
});

/**
 * @swagger
 * /totp/disable:
 *   post:
 *     summary: Disable 2FA
 *     description: Disables TOTP 2FA and clears the secret. Requires auth.
 *     tags: [TOTP]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: 2FA disabled
 *       401:
 *         description: Unauthorized
 */
// POST /totp/disable - disable 2FA
router.post('/disable', requireAuth, async (req, res) => {
  await users.disableTotp(req.user.id);
  res.json({ ok: true });
});

module.exports = router;
