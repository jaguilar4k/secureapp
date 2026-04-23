'use strict';

const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }

  if (req.session && req.method === 'GET' && !req.session.returnTo) {
    req.session.returnTo = req.originalUrl;
  }

  return res.redirect('/auth/login');
}

function getTokenFromRequest(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice('Bearer '.length).trim();
  }

  if (req.cookies && req.cookies.auth_token) {
    return req.cookies.auth_token;
  }

  return null;
}

function requireJWT(req, res, next) {
  const token = getTokenFromRequest(req);

  if (!token) {
    return res.status(401).json({ error: 'Token JWT requerido.' });
  }

  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header || decoded.header.alg === 'none') {
      return res.status(401).json({ error: 'Algoritmo JWT no permitido.' });
    }
  } catch {
    return res.status(401).json({ error: 'Token invalido.' });
  }

  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, payload) => {
    if (err) {
      const message = err.name === 'TokenExpiredError' ? 'Token expirado.' : 'Token invalido.';
      return res.status(401).json({ error: message });
    }

    req.jwtUser = payload;
    return next();
  });
}

module.exports = { getTokenFromRequest, requireAuth, requireJWT };
