'use strict';
const express = require('express');
const db      = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

const router = express.Router();

// RF-06: El log solo es visible para SuperAdmin
router.get('/', requireAuth, requireRole('SuperAdmin'), async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 50;
    const offset = (page - 1) * limit;

    const [logRes, countRes] = await Promise.all([
      db.query(
        `SELECT al.*, u.email
         FROM audit_log al
         LEFT JOIN usuarios u ON u.id = al.usuario_id
         ORDER BY al.timestamp DESC
         LIMIT $1 OFFSET $2`,
        [limit, offset]
      ),
      db.query('SELECT COUNT(*) FROM audit_log'),
    ]);

    const totalPages = Math.ceil(parseInt(countRes.rows[0].count) / limit);

    res.render('audit/index', {
      logs: logRes.rows,
      user: req.session.user,
      page,
      totalPages,
    });
  } catch (err) {
    console.error(err);
    res.status(500).render('error', { titulo: 'Error', mensaje: 'Error al cargar logs.', user: req.session.user });
  }
});

module.exports = router;
