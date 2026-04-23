'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { registrarEvento, getIP } = require('../middleware/audit');
const { buildHttpOnlyCookieOptions, getSessionRuntimeConfig } = require('../config/session');

const router = express.Router();
const sessionRuntime = getSessionRuntimeConfig();

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  handler: async (req, res) => {
    const ip = getIP(req);
    await registrarEvento({
      ip,
      userId: null,
      username: req.body.username || 'desconocido',
      evento: 'RATE_LIMIT_LOGIN',
      detalle: `IP ${ip} bloqueada por exceso de intentos de login`,
      ruta: '/auth/login',
      resultado: 'fallido',
    });

    return res.status(429).render('auth/login', {
      error: 'Demasiados intentos fallidos. Tu IP esta bloqueada por 5 minutos.',
      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : '',
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
});

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');

  return res.render('auth/login', {
    error: null,
    csrfToken: req.csrfToken(),
  });
});

router.post(
  '/login',
  loginLimiter,
  [
    body('username').trim().notEmpty().withMessage('Usuario requerido.'),
    body('password').notEmpty().withMessage('Contrasena requerida.'),
  ],
  async (req, res) => {
    const ip = getIP(req);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.render('auth/login', {
        error: errors.array()[0].msg,
        csrfToken: req.csrfToken(),
      });
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

      if (!user || !user.activo) {
        await registrarEvento({
          ip,
          userId: null,
          username,
          evento: 'LOGIN_FALLIDO',
          detalle: 'Usuario no encontrado o inactivo',
          ruta: '/auth/login',
          resultado: 'fallido',
        });

        return res.render('auth/login', {
          error: 'Credenciales incorrectas.',
          csrfToken: req.csrfToken(),
        });
      }

      const passwordMatches = await bcrypt.compare(password, user.password_hash);
      if (!passwordMatches) {
        await registrarEvento({
          ip,
          userId: user.id,
          username,
          evento: 'LOGIN_FALLIDO',
          detalle: 'Contrasena incorrecta',
          ruta: '/auth/login',
          resultado: 'fallido',
        });

        return res.render('auth/login', {
          error: 'Credenciales incorrectas.',
          csrfToken: req.csrfToken(),
        });
      }

      const returnTo = req.session.returnTo || '/dashboard';

      return req.session.regenerate(async (err) => {
        if (err) {
          console.error('[AUTH] Error regenerando sesion:', err);
          return res.render('auth/login', {
            error: 'Error interno.',
            csrfToken: req.csrfToken(),
          });
        }

        try {
          req.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            rol: user.rol,
          };

          req.session.returnTo = returnTo;

          await db.query(
            'UPDATE usuarios SET ultimo_login = NOW(), ultimo_login_ip = $1 WHERE id = $2',
            [ip, user.id]
          );

          await registrarEvento({
            ip,
            userId: user.id,
            username,
            evento: 'LOGIN_EXITOSO',
            detalle: `Login exitoso. Rol: ${user.rol}`,
            ruta: '/auth/login',
            resultado: 'exitoso',
          });

          const redirectTarget = req.session.returnTo || '/dashboard';
          delete req.session.returnTo;

          return req.session.save((saveErr) => {
            if (saveErr) {
              console.error('[AUTH] Error guardando sesion:', saveErr);
              return res.render('auth/login', {
                error: 'Error interno.',
                csrfToken: req.csrfToken(),
              });
            }

            return res.redirect(redirectTarget);
          });
        } catch (callbackError) {
          console.error('[AUTH] Error finalizando login:', callbackError);
          return res.render('auth/login', {
            error: 'Error interno del servidor.',
            csrfToken: req.csrfToken(),
          });
        }
      });
    } catch (err) {
      console.error('[AUTH] Error en login:', err);
      return res.render('auth/login', {
        error: 'Error interno del servidor.',
        csrfToken: req.csrfToken(),
      });
    }
  }
);

router.post('/logout', async (req, res) => {
  const user = req.session.user;
  const ip = getIP(req);

  if (user) {
    await registrarEvento({
      ip,
      userId: user.id,
      username: user.username,
      evento: 'LOGOUT',
      detalle: 'Cierre de sesion',
      ruta: '/auth/logout',
      resultado: 'exitoso',
    });
  }

  return req.session.destroy((err) => {
    if (err) {
      console.error('[AUTH] Error destruyendo sesion:', err);
    }

    res.clearCookie('connect.sid', buildHttpOnlyCookieOptions(req, { runtime: sessionRuntime }));
    res.clearCookie('auth_token', buildHttpOnlyCookieOptions(req, { runtime: sessionRuntime }));
    return res.redirect('/auth/login');
  });
});

module.exports = router;
