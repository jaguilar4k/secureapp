'use strict';

const express = require('express');
const { body, param, validationResult } = require('express-validator');
const db = require('../../db');
const { requireJWT } = require('../../middleware/auth');
const { requireRoleAPI } = require('../../middleware/rbac');
const { registrarEvento, getIP } = require('../../middleware/audit');

const router = express.Router();

router.use(requireJWT);

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
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 500 }).withMessage('Descripcion max 500 caracteres.'),
  body('cantidad')
    .isInt({ min: 0 }).withMessage('Cantidad invalida.'),
  body('precio')
    .isFloat({ min: 0 }).withMessage('Precio invalido.'),
];

const idValidation = [
  param('id').isInt({ min: 1 }).withMessage('ID de producto invalido.'),
];

function getValidationErrors(req) {
  const errors = validationResult(req);
  return errors.isEmpty() ? [] : errors.array();
}

router.get('/', requireRoleAPI('SuperAdmin', 'Auditor', 'Registrador'), async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.*, u.username AS creado_por_nombre
       FROM productos p
       LEFT JOIN usuarios u ON u.id = p.creado_por
       ORDER BY p.created_at DESC`
    );

    return res.json(result.rows);
  } catch (err) {
    console.error('[API PRODUCTS] Error listando productos:', err);
    return res.status(500).json({ error: 'Error interno.' });
  }
});

router.get('/:id', requireRoleAPI('SuperAdmin', 'Auditor', 'Registrador'), idValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  try {
    const result = await db.query('SELECT * FROM productos WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Producto no encontrado.' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    console.error('[API PRODUCTS] Error cargando producto:', err);
    return res.status(500).json({ error: 'Error interno.' });
  }
});

router.post('/', requireRoleAPI('SuperAdmin', 'Registrador'), productoValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  const { codigo, nombre, descripcion, cantidad, precio } = req.body;

  try {
    const result = await db.query(
      `INSERT INTO productos (codigo, nombre, descripcion, cantidad, precio, creado_por)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        codigo,
        nombre,
        descripcion || null,
        Number.parseInt(cantidad, 10),
        Number.parseFloat(precio),
        req.jwtUser.sub,
      ]
    );

    await registrarEvento({
      ip: getIP(req),
      userId: req.jwtUser.sub,
      username: req.jwtUser.username,
      evento: 'API_PRODUCTO_CREADO',
      detalle: `${codigo} - ${nombre}`,
      ruta: '/api/productos',
      resultado: 'exitoso',
    });

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Codigo de producto ya existe.' });
    }

    console.error('[API PRODUCTS] Error creando producto:', err);
    return res.status(500).json({ error: 'Error interno.' });
  }
});

router.put(
  '/:id',
  requireRoleAPI('SuperAdmin', 'Registrador'),
  [...idValidation, ...productoValidation],
  async (req, res) => {
    const errors = getValidationErrors(req);
    if (errors.length > 0) {
      return res.status(400).json({ errors });
    }

    const { codigo, nombre, descripcion, cantidad, precio } = req.body;

    try {
      const result = await db.query(
        `UPDATE productos
         SET codigo = $1, nombre = $2, descripcion = $3, cantidad = $4, precio = $5, updated_at = NOW()
         WHERE id = $6
         RETURNING *`,
        [
          codigo,
          nombre,
          descripcion || null,
          Number.parseInt(cantidad, 10),
          Number.parseFloat(precio),
          req.params.id,
        ]
      );

      if (!result.rows[0]) {
        return res.status(404).json({ error: 'Producto no encontrado.' });
      }

      await registrarEvento({
        ip: getIP(req),
        userId: req.jwtUser.sub,
        username: req.jwtUser.username,
        evento: 'API_PRODUCTO_EDITADO',
        detalle: `ID:${req.params.id} -> ${codigo} - ${nombre}`,
        ruta: `/api/productos/${req.params.id}`,
        resultado: 'exitoso',
      });

      return res.json(result.rows[0]);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'Codigo de producto ya existe.' });
      }

      console.error('[API PRODUCTS] Error actualizando producto:', err);
      return res.status(500).json({ error: 'Error interno.' });
    }
  }
);

router.delete('/:id', requireRoleAPI('SuperAdmin', 'Registrador'), idValidation, async (req, res) => {
  const errors = getValidationErrors(req);
  if (errors.length > 0) {
    return res.status(400).json({ errors });
  }

  try {
    const result = await db.query(
      'DELETE FROM productos WHERE id = $1 RETURNING codigo, nombre',
      [req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Producto no encontrado.' });
    }

    await registrarEvento({
      ip: getIP(req),
      userId: req.jwtUser.sub,
      username: req.jwtUser.username,
      evento: 'API_PRODUCTO_ELIMINADO',
      detalle: `ID:${req.params.id} - ${result.rows[0].codigo} - ${result.rows[0].nombre}`,
      ruta: `/api/productos/${req.params.id}`,
      resultado: 'exitoso',
    });

    return res.json({ message: 'Producto eliminado.' });
  } catch (err) {
    console.error('[API PRODUCTS] Error eliminando producto:', err);
    return res.status(500).json({ error: 'Error interno.' });
  }
});

module.exports = router;
