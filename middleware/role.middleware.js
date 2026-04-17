// backend/middleware/role.middleware.js

const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    return next();
  }
  return res.status(403).json({ message: 'Access denied - Admins only' });
};

const memberOrAdmin = (req, res, next) => {
  if (req.user && (req.user.role === 'member' || req.user.role === 'admin')) {
    return next();
  }
  return res.status(403).json({ message: 'Access denied - Members only' });
};

module.exports = { adminOnly, memberOrAdmin };