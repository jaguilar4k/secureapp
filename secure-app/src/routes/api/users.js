'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, param, validationResult } = require('express-validator');
const db = require('../../db');
const { requireJWT } = require('../../middleware/auth');
const { requireRoleAPI } = require('../../middleware/rbac');
const { registrarEvento, getIP } = require('../../middleware/audit');
const { buildHttpOnlyCookieOptions, getSessionRuntimeConfig } = require('../../config/session');
const {
  assertCanChangeUserRole,
  assertCanDeleteUser,
  assertRoleExists,
} = require('../../services/user-admin');

const router = express.Router();
const BCRYPT_COST = 12;
const sessionRuntime = getSessionRuntimeConfig();

router.use(requireJWT);

const idValidation = [
  param('id').isInt({ min: 1 }).withMessage('ID de usuario invalido.'),
];

const userCreateValidation = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username requerido.')
    .isLength({ min: 3, max: 50 }).withMessage('Username: 3-50 caracteres.'),
  body('email')
    .trim()
    .isEmail().withMessage('Email invalido.')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 }).withMessage('Contrasena minimo 8 caracteres.')
    .matches(/[A-Z]/).withMessage('Contrasena debe contener al menos una mayuscula.')
    .matches(/[0-9]/).withMessage('Contrasena debe contener al menos un numero.'),
  body('rol_id').isInt({ min: 1 }).withMessage('Rol requerido.'),
];

const userEditValidation = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username requerido.')
    .isLength({ min: 3, max: 50 }).withMessage('Username: 3-50 caracteres.'),
  body('email')
    .trim()
    .isEmail().withMessage('Email invalido.')
    .normalizeEmail(),
  body('rol_id').isInt({ min: 1 }).withMessage('Rol requerido.'),
  body('password')
    .optional({ checkFalsy: true })
    .isLength({ min: 8 }).withMessage('Contrasena minimo 8 caracteres.')
    .matches(/[A-Z]/).withMessage('Contrasena debe contener al menos una mayuscula.')
    .matches(/[0-9]/).withMessage('Contrasena debe contener al menos un numero.'),
];

function getValidationErrors(req) {
  const errors = validationResult(req);
  return errors.isEmpty() ? [] : errors.array();
}

function getJwtExpirySeconds() {
  const value = Number.parseInt(process.env.JWT_EXPIRY || '3600', 10);
  if (Number.isNaN(value) || value <= 0) return 3600;
  return Math.min(value, 3600);
}

router.get('/', requireRoleAPI('SuperAdmin', 'Auditor', 'Registrador'), async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.username, u.email, r.nombre AS rol, u.activo, u.ultimo_login, u.ultimo_login_ip
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       ORDER BY u.created_at DESC`
    );

    return res.json(result.rows);
  } catch (err) {
    console.error('[API USERS] Error listando usuarios:', err);
    return res.status(500).json({ error: 'Error interno.' });
  }
});

router.get('/:id', requireRoleAPI('SuperAdmin'), idValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  try {
    const result = await db.query(
      `SELECT u.id, u.username, u.email, r.nombre AS rol, u.activo, u.ultimo_login, u.ultimo_login_ip
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       WHERE u.id = $1`,
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    console.error('[API USERS] Error cargando usuario:', err);
    return res.status(500).json({ error: 'Error interno.' });
  }
});

router.post('/', requireRoleAPI('SuperAdmin'), userCreateValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const { username, email, password, rol_id } = req.body;
  const roleId = Number.parseInt(rol_id, 10);

  try {
    await assertRoleExists(roleId);

    const hash = await bcrypt.hash(password, BCRYPT_COST);
    const result = await db.query(
      `INSERT INTO usuarios (username, password_hash, email, rol_id)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email`,
      [username, hash, email, roleId]
    );

    await registrarEvento({
      ip: getIP(req),
      userId: req.jwtUser.sub,
      username: req.jwtUser.username,
      evento: 'API_USUARIO_CREADO',
      detalle: `${username} (${email}) con rol_id=${roleId}`,
      ruta: '/api/usuarios',
      resultado: 'exitoso',
    });

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    const statusCode = err.statusCode || (err.code === '23505' ? 409 : 500);
    const message = err.code === '23505'
      ? 'Username o email ya existe.'
      : err.message || 'Error interno.';

    return res.status(statusCode).json({ error: message });
  }
});

router.put(
  '/:id',
  requireRoleAPI('SuperAdmin'),
  [...idValidation, ...userEditValidation],
  async (req, res) => {
    const errors = getValidationErrors(req);
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    }

    const userId = Number.parseInt(req.params.id, 10);
    const roleId = Number.parseInt(req.body.rol_id, 10);
    const { username, email, password } = req.body;

    try {
      const { nextRole } = await assertCanChangeUserRole(userId, roleId);

      const params = [username, email, roleId, userId];
      let updateQuery = `
        UPDATE usuarios
        SET username = $1, email = $2, rol_id = $3
        WHERE id = $4
        RETURNING id, username, email
      `;

      if (password && password.trim() !== '') {
        const hash = await bcrypt.hash(password.trim(), BCRYPT_COST);
        params.splice(2, 0, hash);
        updateQuery = `
          UPDATE usuarios
          SET username = $1, email = $2, password_hash = $3, rol_id = $4
          WHERE id = $5
          RETURNING id, username, email
        `;
      }

      const result = await db.query(updateQuery, params);
      if (!result.rows[0]) {
        return res.status(404).json({ error: 'Usuario no encontrado.' });
      }

      let refreshedToken = null;
      if (req.jwtUser.sub === userId) {
        const expiresIn = getJwtExpirySeconds();
        refreshedToken = jwt.sign(
          { sub: userId, username, email, rol: nextRole.nombre },
          process.env.JWT_SECRET,
          { algorithm: 'HS256', expiresIn }
        );

        res.cookie(
          'auth_token',
          refreshedToken,
          buildHttpOnlyCookieOptions(req, {
            runtime: sessionRuntime,
            maxAge: expiresIn * 1000,
          })
        );
      }

      await registrarEvento({
        ip: getIP(req),
        userId: req.jwtUser.sub,
        username: req.jwtUser.username,
        evento: 'API_USUARIO_EDITADO',
        detalle: `Usuario ID:${userId} editado -> ${username}, rol=${nextRole.nombre}`,
        ruta: `/api/usuarios/${userId}`,
        resultado: 'exitoso',
      });

      return res.json({
        user: { id: userId, username, email, rol: nextRole.nombre },
        refreshedToken,
      });
    } catch (err) {
      const statusCode = err.statusCode || (err.code === '23505' ? 409 : 500);
      const message = err.code === '23505'
        ? 'Username o email ya existe.'
        : err.message || 'Error interno.';

      return res.status(statusCode).json({ error: message });
    }
  }
);

router.delete('/:id', requireRoleAPI('SuperAdmin'), idValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const userId = Number.parseInt(req.params.id, 10);

  if (userId === req.jwtUser.sub) {
    return res.status(400).json({ error: 'No puedes eliminarte a ti mismo.' });
  }

  try {
    await assertCanDeleteUser(userId);

    const result = await db.query('DELETE FROM usuarios WHERE id = $1 RETURNING username', [userId]);
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Usuario no encontrado.' });
    }

    await registrarEvento({
      ip: getIP(req),
      userId: req.jwtUser.sub,
      username: req.jwtUser.username,
      evento: 'API_USUARIO_ELIMINADO',
      detalle: `ID:${userId} - ${result.rows[0].username}`,
      ruta: `/api/usuarios/${userId}`,
      resultado: 'exitoso',
    });

    return res.json({ message: 'Usuario eliminado.' });
  } catch (err) {
    const statusCode = err.statusCode || 500;
    return res.status(statusCode).json({ error: err.message || 'Error interno.' });
  }
});

module.exports = router;
