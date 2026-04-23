'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const { body, param, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireAnyRole, requireRole } = require('../middleware/rbac');
const { registrarEvento, getIP } = require('../middleware/audit');
const {
  assertCanChangeUserRole,
  assertCanDeleteUser,
  assertRoleExists,
} = require('../services/user-admin');

const router = express.Router();

router.use(requireAuth);

const BCRYPT_COST = 12;

const idValidation = [
  param('id').isInt({ min: 1 }).withMessage('ID de usuario invalido.'),
];

const passwordStrengthValidation = body('password')
  .isLength({ min: 8 }).withMessage('Contrasena minimo 8 caracteres.')
  .matches(/[A-Z]/).withMessage('Contrasena debe contener al menos una mayuscula.')
  .matches(/[0-9]/).withMessage('Contrasena debe contener al menos un numero.');

const userCreateValidation = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username requerido.')
    .isLength({ min: 3, max: 50 }).withMessage('Username: 3-50 caracteres.'),
  body('email')
    .trim()
    .isEmail().withMessage('Email invalido.')
    .normalizeEmail(),
  passwordStrengthValidation,
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

function renderError(res, user, statusCode, message) {
  return res.status(statusCode).render('error', {
    titulo: String(statusCode),
    mensaje: message,
    user,
  });
}

async function loadRoles() {
  const result = await db.query('SELECT * FROM roles ORDER BY id');
  return result.rows;
}

async function renderUserForm(res, req, { titulo, usuario, errors }) {
  const roles = await loadRoles();
  return res.render('users/form', {
    titulo,
    usuario,
    roles,
    errors,
    user: req.session.user,
    csrfToken: req.csrfToken(),
  });
}

router.get('/', requireAnyRole('SuperAdmin', 'Auditor', 'Registrador'), async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.username, u.email, r.nombre AS rol,
              u.activo, u.ultimo_login, u.ultimo_login_ip, u.created_at
       FROM usuarios u
       JOIN roles r ON r.id = u.rol_id
       ORDER BY u.created_at DESC`
    );

    return res.render('users/index', {
      usuarios: result.rows,
      user: req.session.user,
      success: req.query.success || null,
    });
  } catch (err) {
    console.error('[USERS] Error listando usuarios:', err);
    return renderError(res, req.session.user, 500, 'Error al cargar usuarios.');
  }
});

router.get('/nuevo', requireRole('SuperAdmin'), async (req, res) => {
  try {
    return await renderUserForm(res, req, {
      titulo: 'Nuevo Usuario',
      usuario: {},
      errors: [],
    });
  } catch (err) {
    console.error('[USERS] Error cargando formulario de usuario:', err);
    return renderError(res, req.session.user, 500, 'Error al cargar el formulario de usuario.');
  }
});

router.post('/nuevo', requireRole('SuperAdmin'), userCreateValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return renderUserForm(res, req, {
      titulo: 'Nuevo Usuario',
      usuario: req.body,
      errors,
    });
  }

  const { username, email, password, rol_id } = req.body;
  const user = req.session.user;
  const ip = getIP(req);
  const roleId = Number.parseInt(rol_id, 10);

  try {
    await assertRoleExists(roleId);

    const hash = await bcrypt.hash(password, BCRYPT_COST);
    await db.query(
      `INSERT INTO usuarios (username, password_hash, email, rol_id)
       VALUES ($1, $2, $3, $4)`,
      [username, hash, email, roleId]
    );

    await registrarEvento({
      ip,
      userId: user.id,
      username: user.username,
      evento: 'USUARIO_CREADO',
      detalle: `Usuario creado: ${username} (${email}) con rol_id=${roleId}`,
      ruta: '/usuarios/nuevo',
      resultado: 'exitoso',
    });

    return res.redirect('/usuarios?success=Usuario+creado+exitosamente');
  } catch (err) {
    const statusCode = err.statusCode || 500;
    const message = err.code === '23505'
      ? 'El username o email ya existe.'
      : err.message || 'Error al crear usuario.';

    return statusCode >= 500
      ? renderUserForm(res, req, {
          titulo: 'Nuevo Usuario',
          usuario: req.body,
          errors: [{ msg: 'Error al crear usuario.' }],
        })
      : renderUserForm(res, req, {
          titulo: 'Nuevo Usuario',
          usuario: req.body,
          errors: [{ msg: message }],
        });
  }
});

router.get('/:id/editar', requireRole('SuperAdmin'), idValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return renderError(res, req.session.user, 400, errors[0].msg);
  }

  try {
    const userResult = await db.query(
      'SELECT id, username, email, rol_id, activo FROM usuarios WHERE id = $1',
      [req.params.id]
    );

    if (!userResult.rows[0]) {
      return renderError(res, req.session.user, 404, 'Usuario no encontrado.');
    }

    return renderUserForm(res, req, {
      titulo: 'Editar Usuario',
      usuario: userResult.rows[0],
      errors: [],
    });
  } catch (err) {
    console.error('[USERS] Error cargando usuario:', err);
    return renderError(res, req.session.user, 500, 'Error al cargar usuario.');
  }
});

router.post(
  '/:id/editar',
  requireRole('SuperAdmin'),
  [...idValidation, ...userEditValidation],
  async (req, res) => {
    const errors = getValidationErrors(req);
    const userId = Number.parseInt(req.params.id, 10);

    if (errors.length > 0) {
      return renderUserForm(res, req, {
        titulo: 'Editar Usuario',
        usuario: { ...req.body, id: userId },
        errors,
      });
    }

    const { username, email, password, rol_id } = req.body;
    const currentUser = req.session.user;
    const ip = getIP(req);
    const roleId = Number.parseInt(rol_id, 10);

    try {
      const { nextRole, user: targetUser } = await assertCanChangeUserRole(userId, roleId);

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

      const updateResult = await db.query(updateQuery, params);
      if (!updateResult.rows[0]) {
        return renderError(res, currentUser, 404, 'Usuario no encontrado.');
      }

      if (currentUser.id === userId) {
        req.session.user = {
          ...req.session.user,
          username,
          email,
          rol: nextRole.nombre,
        };
      }

      await registrarEvento({
        ip,
        userId: currentUser.id,
        username: currentUser.username,
        evento: 'USUARIO_EDITADO',
        detalle: `Usuario ID:${userId} editado -> ${username}, rol=${nextRole.nombre}`,
        ruta: `/usuarios/${userId}/editar`,
        resultado: 'exitoso',
      });

      return res.redirect('/usuarios?success=Usuario+actualizado');
    } catch (err) {
      const message = err.code === '23505'
        ? 'El username o email ya existe.'
        : err.message || 'Error al actualizar usuario.';

      return renderUserForm(res, req, {
        titulo: 'Editar Usuario',
        usuario: { ...req.body, id: userId },
        errors: [{ msg: message }],
      });
    }
  }
);

router.post('/:id/eliminar', requireRole('SuperAdmin'), idValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return renderError(res, req.session.user, 400, errors[0].msg);
  }

  const userId = Number.parseInt(req.params.id, 10);
  const currentUser = req.session.user;
  const ip = getIP(req);

  if (userId === currentUser.id) {
    return renderError(res, currentUser, 400, 'No puedes eliminar tu propio usuario.');
  }

  try {
    await assertCanDeleteUser(userId);

    const result = await db.query('DELETE FROM usuarios WHERE id = $1 RETURNING username', [userId]);
    if (!result.rows[0]) {
      return renderError(res, currentUser, 404, 'Usuario no encontrado.');
    }

    await registrarEvento({
      ip,
      userId: currentUser.id,
      username: currentUser.username,
      evento: 'USUARIO_ELIMINADO',
      detalle: `Usuario eliminado ID:${userId} - ${result.rows[0].username}`,
      ruta: `/usuarios/${userId}/eliminar`,
      resultado: 'exitoso',
    });

    return res.redirect('/usuarios?success=Usuario+eliminado');
  } catch (err) {
    const statusCode = err.statusCode || 500;
    return renderError(
      res,
      currentUser,
      statusCode,
      err.message || 'Error al eliminar usuario.'
    );
  }
});

module.exports = router;
