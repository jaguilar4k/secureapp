'use strict';

const express = require('express');
const { body, param, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireAnyRole } = require('../middleware/rbac');
const { registrarEvento, getIP } = require('../middleware/audit');

const router = express.Router();

router.use(requireAuth);

const productoValidation = [
  body('codigo')
    .trim()
    .notEmpty().withMessage('Codigo requerido.')
    .matches(/^[A-Za-z0-9\-_]{1,20}$/).withMessage('Codigo alfanumerico, max 20 caracteres.'),
  body('nombre')
    .trim()
    .notEmpty().withMessage('Nombre requerido.')
    .isLength({ max: 100 }).withMessage('Nombre max 100 caracteres.'),
  body('descripcion')
    .trim()
    .optional({ checkFalsy: true })
    .isLength({ max: 500 }).withMessage('Descripcion max 500 caracteres.'),
  body('cantidad')
    .isInt({ min: 0 }).withMessage('Cantidad debe ser un entero >= 0.'),
  body('precio')
    .isFloat({ min: 0 }).withMessage('Precio debe ser >= 0.'),
];

const idValidation = [
  param('id').isInt({ min: 1 }).withMessage('ID de producto invalido.'),
];

function renderError(res, user, statusCode, message) {
  return res.status(statusCode).render('error', {
    titulo: String(statusCode),
    mensaje: message,
    user,
  });
}

function getValidationErrors(req) {
  const errors = validationResult(req);
  return errors.isEmpty() ? [] : errors.array();
}

router.get('/', requireAnyRole('SuperAdmin', 'Auditor', 'Registrador'), async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.*, u.username AS creado_por_nombre
       FROM productos p
       LEFT JOIN usuarios u ON u.id = p.creado_por
       ORDER BY p.created_at DESC`
    );

    return res.render('products/index', {
      productos: result.rows,
      user: req.session.user,
      success: req.query.success || null,
    });
  } catch (err) {
    console.error('[PRODUCTS] Error cargando productos:', err);
    return renderError(res, req.session.user, 500, 'Error al cargar productos.');
  }
});

router.get('/nuevo', requireAnyRole('SuperAdmin', 'Registrador'), (req, res) => {
  return res.render('products/form', {
    titulo: 'Nuevo Producto',
    producto: {},
    errors: [],
    user: req.session.user,
    csrfToken: req.csrfToken(),
  });
});

router.post(
  '/nuevo',
  requireAnyRole('SuperAdmin', 'Registrador'),
  productoValidation,
  async (req, res) => {
    const errors = getValidationErrors(req);
    if (errors.length > 0) {
      return res.render('products/form', {
        titulo: 'Nuevo Producto',
        producto: req.body,
        errors,
        user: req.session.user,
        csrfToken: req.csrfToken(),
      });
    }

    const { codigo, nombre, descripcion, cantidad, precio } = req.body;
    const user = req.session.user;
    const ip = getIP(req);

    try {
      await db.query(
        `INSERT INTO productos (codigo, nombre, descripcion, cantidad, precio, creado_por)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          codigo,
          nombre,
          descripcion || null,
          Number.parseInt(cantidad, 10),
          Number.parseFloat(precio),
          user.id,
        ]
      );

      await registrarEvento({
        ip,
        userId: user.id,
        username: user.username,
        evento: 'PRODUCTO_CREADO',
        detalle: `Producto creado: ${codigo} - ${nombre}`,
        ruta: '/productos/nuevo',
        resultado: 'exitoso',
      });

      return res.redirect('/productos?success=Producto+creado+exitosamente');
    } catch (err) {
      const message = err.code === '23505'
        ? 'El codigo de producto ya existe.'
        : 'Error al crear producto.';

      return res.render('products/form', {
        titulo: 'Nuevo Producto',
        producto: req.body,
        errors: [{ msg: message }],
        user,
        csrfToken: req.csrfToken(),
      });
    }
  }
);

router.get(
  '/:id/editar',
  requireAnyRole('SuperAdmin', 'Registrador'),
  idValidation,
  async (req, res) => {
    const errors = getValidationErrors(req);
    if (errors.length > 0) {
      return renderError(res, req.session.user, 400, errors[0].msg);
    }

    try {
      const result = await db.query('SELECT * FROM productos WHERE id = $1', [req.params.id]);
      if (!result.rows[0]) {
        return renderError(res, req.session.user, 404, 'Producto no encontrado.');
      }

      return res.render('products/form', {
        titulo: 'Editar Producto',
        producto: result.rows[0],
        errors: [],
        user: req.session.user,
        csrfToken: req.csrfToken(),
      });
    } catch (err) {
      console.error('[PRODUCTS] Error cargando producto:', err);
      return renderError(res, req.session.user, 500, 'Error al cargar producto.');
    }
  }
);

router.post(
  '/:id/editar',
  requireAnyRole('SuperAdmin', 'Registrador'),
  [...idValidation, ...productoValidation],
  async (req, res) => {
    const errors = getValidationErrors(req);
    const productId = Number.parseInt(req.params.id, 10);

    if (errors.length > 0) {
      return res.render('products/form', {
        titulo: 'Editar Producto',
        producto: { ...req.body, id: productId },
        errors,
        user: req.session.user,
        csrfToken: req.csrfToken(),
      });
    }

    const { codigo, nombre, descripcion, cantidad, precio } = req.body;
    const user = req.session.user;
    const ip = getIP(req);

    try {
      const result = await db.query(
        `UPDATE productos
         SET codigo = $1, nombre = $2, descripcion = $3, cantidad = $4, precio = $5, updated_at = NOW()
         WHERE id = $6
         RETURNING id`,
        [
          codigo,
          nombre,
          descripcion || null,
          Number.parseInt(cantidad, 10),
          Number.parseFloat(precio),
          productId,
        ]
      );

      if (!result.rows[0]) {
        return renderError(res, user, 404, 'Producto no encontrado.');
      }

      await registrarEvento({
        ip,
        userId: user.id,
        username: user.username,
        evento: 'PRODUCTO_EDITADO',
        detalle: `Producto editado ID:${productId} -> ${codigo} - ${nombre}`,
        ruta: `/productos/${productId}/editar`,
        resultado: 'exitoso',
      });

      return res.redirect('/productos?success=Producto+actualizado');
    } catch (err) {
      const message = err.code === '23505'
        ? 'El codigo de producto ya existe.'
        : 'Error al actualizar producto.';

      return res.render('products/form', {
        titulo: 'Editar Producto',
        producto: { ...req.body, id: productId },
        errors: [{ msg: message }],
        user,
        csrfToken: req.csrfToken(),
      });
    }
  }
);

router.post(
  '/:id/eliminar',
  requireAnyRole('SuperAdmin', 'Registrador'),
  idValidation,
  async (req, res) => {
    const errors = getValidationErrors(req);
    if (errors.length > 0) {
      return renderError(res, req.session.user, 400, errors[0].msg);
    }

    const productId = Number.parseInt(req.params.id, 10);
    const user = req.session.user;
    const ip = getIP(req);

    try {
      const result = await db.query(
        'DELETE FROM productos WHERE id = $1 RETURNING codigo, nombre',
        [productId]
      );

      if (!result.rows[0]) {
        return renderError(res, user, 404, 'Producto no encontrado.');
      }

      const { codigo, nombre } = result.rows[0];
      await registrarEvento({
        ip,
        userId: user.id,
        username: user.username,
        evento: 'PRODUCTO_ELIMINADO',
        detalle: `Producto eliminado ID:${productId} - ${codigo} - ${nombre}`,
        ruta: `/productos/${productId}/eliminar`,
        resultado: 'exitoso',
      });

      return res.redirect('/productos?success=Producto+eliminado');
    } catch (err) {
      console.error('[PRODUCTS] Error eliminando producto:', err);
      return renderError(res, user, 500, 'Error al eliminar producto.');
    }
  }
);

module.exports = router;
