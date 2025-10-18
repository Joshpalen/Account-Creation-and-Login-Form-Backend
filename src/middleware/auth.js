const jwt = require('jsonwebtoken');
const config = require('../config');

const JWT_SECRET = config.JWT_SECRET;

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'missing token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Normalize common fields
    if (!payload.id && payload.sub) payload.id = payload.sub;
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin access required' });
  }
  next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions || !req.user.permissions.split(',').includes(permission)) {
      return res.status(403).json({ error: 'permission denied' });
    }
    next();
  };
}

module.exports = { requireAuth, requireAdmin, requirePermission };
