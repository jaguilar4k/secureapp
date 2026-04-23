'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const db = require('../../db');
const { registrarEvento, getIP } = require('../../middleware/audit');
const { buildHttpOnlyCookieOptions, getSessionRuntimeConfig } = require('../../config/session');

const router = express.Router();
const sessionRuntime = getSessionRuntimeConfig();

function getJwtExpirySeconds() {
  const value = Number.parseInt(process.env.JWT_EXPIRY || '3600', 10);
  if (Number.isNaN(value) || value <= 0) return 3600;
  return Math.min(value, 3600);
}

const apiLoginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  handler: async (req, res) => {
    const ip = getIP(req);
    await registrarEvento({
      ip,
      userId: null,
      username: req.body.username || 'desconocido',
      evento: 'RATE_LIMIT_API_LOGIN',
      detalle: `IP ${ip} bloqueada`,
      ruta: '/api/auth/login',
      resultado: 'fallido',
    });

    return res.status(429).json({ error: 'Demasiados intentos. Bloqueado 5 minutos.' });
  },
  standardHeaders: true,
  legacyHeaders: false,
});

router.post(
  '/login',
  apiLoginLimiter,
  [
    body('username').trim().notEmpty().withMessage('Usuario requerido.'),
    body('password').notEmpty().withMessage('Contrasena requerida.'),
  ],
  async (req, res) => {
    const ip = getIP(req);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      const result = await db.query(
        `SELECT u.id, u.username, u.password_hash, u.email, u.activo, r.nombre AS rol
         FROM usuarios u
         JOIN roles r ON r.id = u.rol_id
         WHERE u.username = $1`,
        [username]
      );

      const user = result.rows[0];

      if (!user || !user.activo || !(await bcrypt.compare(password, user.password_hash))) {
        await registrarEvento({
          ip,
          userId: user ? user.id : null,
          username,
          evento: 'API_LOGIN_FALLIDO',
          detalle: 'Credenciales invalidas',
          ruta: '/api/auth/login',
          resultado: 'fallido',
        });

        return res.status(401).json({ error: 'Credenciales incorrectas.' });
      }

      const expiresIn = getJwtExpirySeconds();
      const token = jwt.sign(
        { sub: user.id, username: user.username, email: user.email, rol: user.rol },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', expiresIn }
      );

      await db.query(
        'UPDATE usuarios SET ultimo_login = NOW(), ultimo_login_ip = $1 WHERE id = $2',
        [ip, user.id]
      );

      await registrarEvento({
        ip,
        userId: user.id,
        username,
        evento: 'API_LOGIN_EXITOSO',
        detalle: `JWT emitido. Rol: ${user.rol}`,
        ruta: '/api/auth/login',
        resultado: 'exitoso',
      });

      res.cookie(
        'auth_token',
        token,
        buildHttpOnlyCookieOptions(req, {
          runtime: sessionRuntime,
          maxAge: expiresIn * 1000,
        })
      );

      return res.json({
        token,
        tokenType: 'Bearer',
        expiresIn,
        user: { id: user.id, username: user.username, email: user.email, rol: user.rol },
      });
    } catch (err) {
      console.error('[API AUTH]', err);
      return res.status(500).json({ error: 'Error interno del servidor.' });
    }
  }
);

router.post('/logout', async (req, res) => {
  const ip = getIP(req);
  const username = req.body && req.body.username ? req.body.username : 'desconocido';

  await registrarEvento({
    ip,
    userId: null,
    username,
    evento: 'API_LOGOUT',
    detalle: 'JWT invalidado en cliente',
    ruta: '/api/auth/logout',
    resultado: 'exitoso',
  });

  res.clearCookie('auth_token', buildHttpOnlyCookieOptions(req, { runtime: sessionRuntime }));
  return res.json({ message: 'Sesion API cerrada.' });
});

module.exports = router;
